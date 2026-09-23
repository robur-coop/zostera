[@@@warning "-37"]

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let guard ~err fn = if fn () then Ok () else Error err
let strf fmt = Fmt.str fmt
let ( let* ) = Result.bind

(* NOTE(dinosaure): See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2 *)
let hchacha20 ~key ~nonce =
  let s = Array.make 16 0l in
  s.(0) <- 0x61707865l;
  s.(1) <- 0x3320646el;
  s.(2) <- 0x79622d32l;
  s.(3) <- 0x6b206574l;
  for i = 0 to 7 do s.(4+i) <- String.get_int32_le key (i*4) done;
  for i = 0 to 3 do s.(12+i) <- String.get_int32_le nonce (i*4) done;
  let ( <<< ) x n =
    Int32.logor (Int32.shift_left x n) (Int32.shift_right_logical x (32 - n)) in
  let qr a b c d =
    s.(a) <- Int32.add s.(a) s.(b);
    s.(d) <- (Int32.logxor s.(d) s.(a)) <<< 16;
    s.(c) <- Int32.add s.(c) s.(d);
    s.(b) <- (Int32.logxor s.(b) s.(c)) <<< 12;
    s.(a) <- Int32.add s.(a) s.(b);
    s.(d) <- (Int32.logxor s.(d) s.(a)) <<<  8;
    s.(c) <- Int32.add s.(c) s.(d);
    s.(b) <- (Int32.logxor s.(b) s.(c)) <<<  7 in
  for _ = 1 to 10 do
    qr 0 4  8 12;
    qr 1 5  9 13;
    qr 2 6 10 14;
    qr 3 7 11 15;
    qr 0 5 10 15;
    qr 1 6 11 12;
    qr 2 7  8 13;
    qr 3 4  9 14
  done;
  let buf = Bytes.create 32 in
  for i = 0 to 3 do Bytes.set_int32_le buf (i*4) s.(i) done;
  for i = 0 to 3 do Bytes.set_int32_le buf (16+i*4) s.(12+i) done;
  Bytes.unsafe_to_string buf

let xaead ~key ~nonce ?adata msg =
  let key = hchacha20 ~key ~nonce:(String.sub nonce 0 16) in
  let key = Mirage_crypto.Chacha20.of_secret key in
  let nonce = "\x00\x00\x00\x00" ^ String.sub nonce 16 8 in
  Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ?adata msg

let xaead_open ~key ~nonce ?adata msg =
  let key = hchacha20 ~key ~nonce:(String.sub nonce 0 16) in
  let key = Mirage_crypto.Chacha20.of_secret key in
  let nonce = "\x00\x00\x00\x00" ^ String.sub nonce 16 8 in
  Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce ?adata msg

module Addr = Addr
module Limiter = Limiter
module Window = Window
module Uid = Uid

(* NOTE(dinosaure): [B2s] gives to us the real access to the BLAKE2S implementation
   just because [Digestif.Make_BLAKE2S] does not expose [Keyed]... *)
module B2s = struct
  type ctx = bytes

  external ctx_size : unit -> int = "caml_digestif_blake2s_ctx_size" [@@noalloc]
  external with_outlen_and_key : ctx -> int -> string -> int -> int -> unit
    = "caml_digestif_blake2s_st_init_with_outlen_and_key" [@@noalloc]
  external update : ctx -> string -> int -> int -> unit
    = "caml_digestif_blake2s_st_update" [@@noalloc]
  external finalize : ctx -> bytes -> int -> unit
    = "caml_digestif_blake2s_st_finalize" [@@noalloc]
end

let _mac ~key ?(off= 0) ?len buf =
  if String.length key > 32 then invalid_arg "Zostera._mac: invalid key";
  let len = match len with Some len -> len | None -> String.length buf - off in
  if off < 0 || len < 0 || off + len > String.length buf
  then invalid_arg "Zostera._mac: out of bounds";
  let ctx = Bytes.create (B2s.ctx_size ()) in
  B2s.with_outlen_and_key ctx 16 key 0 (String.length key);
  B2s.update ctx buf off len;
  let result = Bytes.create 16 in
  B2s.finalize ctx result 0;
  Bytes.unsafe_to_string result

type error =
  [ `Msg of string | `Invalid_cookie | Mirage_crypto_ec.error ]

let pp_error ppf = function
  | #Mirage_crypto_ec.error as err -> Mirage_crypto_ec.pp_error ppf err
  | `Msg msg -> Fmt.string ppf msg
  | `Invalid_cookie -> Fmt.string ppf "Invalid cookie"

let _COOKIE_LIFETIME = 120_000_000_000

let cookie_key_of_public (_S_pub, _) =
  let open Digestif in
  let _K = BLAKE2S.digest_string (strf "cookie--%s" _S_pub) in
  BLAKE2S.to_raw_string _K

type cookie = { cookie : string; birth : int }

type remote =
  { octets : string
  ; mac1_key : string
  ; cookie_key : string
  ; _SS : string
  ; _Q : string
  ; mutable cookie : cookie option
  ; mutable last_mac1 : mac1 option }
and mac1 = string

let empty = String.make 16 '\x00'

let add_macs ~now (remote : remote) ~off pkt =
  let mac1 = _mac ~key:remote.mac1_key (Bytes.unsafe_to_string pkt) ~off:0 ~len:off in
  Bytes.blit_string mac1 0 pkt off 16;
  remote.last_mac1 <- Some mac1;
  match remote.cookie with
  | Some { cookie; birth } when now < birth + _COOKIE_LIFETIME ->
    let mac2 = _mac ~key:cookie (Bytes.unsafe_to_string pkt) ~off:0 ~len:(off + 16) in
    Bytes.blit_string mac2 0 pkt (off + 16) 16
  | _ -> Bytes.blit_string empty 0 pkt (off + 16) 16

let consume_cookie (remote : remote) ~now ~(uid : Uid.t) pkt =
  let* mac1 = Option.to_result ~none:`Invalid_cookie remote.last_mac1 in
  if String.length pkt <> 64
  || String.get_int32_le pkt 0 <> 3l
  || String.get_int32_le pkt 4 <> (uid :> int32)
  then Error `Invalid_cookie
  else
    let nonce = String.sub pkt 8 24 in
    let str = String.sub pkt 32 32 in
    match xaead_open ~key:remote.cookie_key ~nonce ~adata:mac1 str with
    | Some cookie -> remote.cookie <- Some { cookie; birth= now }; Ok ()
    | None -> Error `Invalid_cookie

type initiator = [ `initiator ]
type responder = [ `responder ]

type pending = |
type confirmed = |

type ('role, 'state) handshake =
  | Initiator : { _Hi : Digestif.BLAKE2S.t
    ; _Ci : string
    ; uid : Uid.t
    ; remote : remote
    ; consumed : bool Atomic.t
    ; _Ei_priv : Mirage_crypto_ec.X25519.secret } -> (initiator, pending) handshake
  | Responder : { _Hr : Digestif.BLAKE2S.t
    ; _Cr : string
    ; remote_uid : Uid.t
    ; remote : remote
    ; uid : Uid.t
    ; consumed : bool Atomic.t
    ; _Er_priv : Mirage_crypto_ec.X25519.secret } -> (responder, confirmed) handshake

let uid_of_initiator (Initiator { uid; _ }) = uid

type psk = string

let psk str =
  if String.length str <> 32 then invalid_arg "Zostera.psk: invalid private shared key";
  str

let _Q = String.make 32 '\000'

type secret = Mirage_crypto_ec.X25519.secret
type public = string * string
type t = secret * public

module Bakery = struct
  type identity = t
  type t =
    { mutable _Rm : string
    ; mutable birth : int
    ; mac1_key : string
    ; cookie_key : string }
  
  let _COOKIE_ROTATION = 120_000_000_000
  
  let secret t ~now =
    (* NOTE(dinosaure): it's lazy roundtrip of [_Rm] *)
    if now - t.birth > _COOKIE_ROTATION then begin
      t._Rm <- Mirage_crypto_rng.generate 32;
      t.birth <- now
    end;
    t._Rm
  
  let create ?g ~me:(_, ((_, mac1_key) as public)) () =
    let cookie_key = cookie_key_of_public public in
    let _Rm = Mirage_crypto_rng.generate ?g 32 in
    { _Rm; birth= 0; mac1_key; cookie_key }
end

let public (_, public) = public

let gen ?g () : secret * public =
  let secret, public = Mirage_crypto_ec.X25519.gen_key ?g () in
  let open Digestif in
  let _K = BLAKE2S.digest_string (strf "mac1----%s" public)
    |> BLAKE2S.to_raw_string in
  (secret, (public, _K))

let public_of_octets str =
  if String.length str <> 32 then invalid_arg "Zostera.public_of_octets: invalid public key";
  let open Digestif in
  let _K = BLAKE2S.digest_string (strf "mac1----%s" str) in
  let _K = BLAKE2S.to_raw_string _K in
  (str, _K)

let octets_of_public (_S_pub, _) = _S_pub

let mix hash str =
  let open Digestif in
  let ctx = BLAKE2S.empty in
  let ctx = BLAKE2S.feed_string ctx (BLAKE2S.to_raw_string hash) in
  let ctx = BLAKE2S.feed_string ctx str in
  BLAKE2S.get ctx

type timestamp = string

let whitener_mask = Int32.sub 0x1000000l 1l

let tai64n ~now =
  let nsecs = Int64.of_int now in
  let secs = Int64.div nsecs 1_000_000_000L in
  let tai = Int64.rem nsecs 1_000_000_000L in
  let secs = Int64.add secs 0x400000000000000AL in
  (* NOTE(dinosaure): as [wireguard-go], we round down the nanoseconds to
     reduce the chance of leaking timing info. See § 5.1:

     > If the precision of a TIA64N poses an unsuitable information leak,
     > implementations may truncate 24 bits of the nanoseconds portion of the
     > timestamp. *)
  let tai = Int32.logand (Int64.to_int32 tai) (Int32.lognot whitener_mask) in
  let buf = Bytes.create 12 in
  Bytes.set_int64_be buf 0 secs;
  Bytes.set_int32_be buf 8 tai;
  Bytes.unsafe_to_string buf

let newer a b = Eqaf.compare_be a b > 0

module Kdf = Hkdf.Make (Digestif.BLAKE2S)

let kdf1 ~ck ~ikm =
  let prk = Kdf.extract ~salt:ck ikm in
  Kdf.expand ~prk 32

let kdf2 ~ck ~ikm =
  let prk = Kdf.extract ~salt:ck ikm in
  let out = Kdf.expand ~prk 64 in
  (String.sub out 0 32, String.sub out 32 32)

let kdf3 ~ck ~ikm =
  let prk = Kdf.extract ~salt:ck ikm in
  let out = Kdf.expand ~prk 96 in
  (String.sub out 0 32, String.sub out 32 32, String.sub out 64 32)

let dh priv pub =
  match Mirage_crypto_ec.X25519.key_exchange priv pub with
  | Ok _ as value -> value
  | Error (#Mirage_crypto_ec.error as err) -> Error err

let aead _k ?(counter= 0L) txt _Hi =
  let nonce = if counter = 0L then String.make 12 '\000'
    else begin
      let buf = Bytes.make 12 '\000' in
      Bytes.set_int64_le buf 4 counter;
      Bytes.unsafe_to_string buf
    end in
  let key = Mirage_crypto.Chacha20.of_secret _k in
  let adata = Digestif.BLAKE2S.to_raw_string _Hi in
  Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ~adata txt

let decrypt _k ?(counter= 0L) txt _Hr =
  let nonce = if counter = 0L then String.make 12 '\000'
    else begin
      let buf = Bytes.make 12 '\000' in
      Bytes.set_int64_le buf 4 counter;
      Bytes.unsafe_to_string buf
    end in
  let key = Mirage_crypto.Chacha20.of_secret _k in
  let adata = Digestif.BLAKE2S.to_raw_string _Hr in
  match Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce ~adata txt with
  | Some plain -> Ok plain
  | None -> error_msgf "AEAD authentication failed"

(* remote *)

let remote ?psk:(_Q= _Q) (_S_priv, _) ((octets, mac1_key) as public : public) =
  let* _SS = dh _S_priv octets in
  let cookie_key = cookie_key_of_public public in
  Ok { octets; mac1_key; cookie_key; _SS; _Q; cookie= None; last_mac1= None }

let remote_of_octets ?psk t str = remote ?psk t (public_of_octets str)
let octets_of_remote { octets; _ } = octets

type msg1 =
  { sender : Uid.t
  ; ephemeral : string
  ; static : string
  ; timestamp : string }

let step0 ?g ?uid ~now ((_, (_Si_pub, _)) : t)
  (({ octets= _Sr_pub; _SS; _ } as remote) : remote) =
  let open Digestif in
  (* Ci := Hash(Construction) *)
  let _Ci = BLAKE2S.digest_string "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" in
  (* Hi := Hash(Ci || Identifier) *)
  let _Hi = mix _Ci "WireGuard v1 zx2c4 Jason@zx2c4.com" in
  let _Ci = BLAKE2S.to_raw_string _Ci in
  (* Hi := Hash(Hi || Sr_pub) *)
  let _Hi = mix _Hi _Sr_pub in
  (* Ei_priv, Ei_pub = DH-Generate() *)
  let _Ei_priv, _Ei_pub = Mirage_crypto_ec.X25519.gen_key ?g () in
  (* Ci := Kdf1(Ci, Ei_pub) *)
  let _Ci = kdf1 ~ck:_Ci ~ikm:_Ei_pub in
  (* msg.ephemeral := Ei_pub *)
  let ephemeral = _Ei_pub in
  (* Hi := Hash(Hi || msg.ephemeral) *)
  let _Hi = mix _Hi ephemeral in
  (* (Ci, k) := Kdf2(Ci, DH(Ei_priv, Sr_pub)) *)
  let* _ES = dh _Ei_priv _Sr_pub in
  let _Ci, _k = kdf2 ~ck:_Ci ~ikm:_ES in
  (* msg.static := Aead(k, 0, Si_pub, Hi) *)
  let static = aead _k _Si_pub _Hi in
  (* Hi := Hash(Hi || msg.static) *)
  let _Hi = mix _Hi static in
  (* (Ci, k) := Kdf2(Ci, DH(Si_priv, Sr_pub) *)
  (* let* _SS = dh _Si_priv _Sr_pub in *)
  let _Ci, _k = kdf2 ~ck:_Ci ~ikm:_SS in
  (* msg.timestamp := Aead(k, 0, Timestamp(), Hi) *)
  let timestamp = aead _k (tai64n ~now) _Hi in
  (* Hi := Hash(Hi || msg.timestamp) *)
  let _Hi = mix _Hi timestamp in
  let uid = match uid with
    | Some uid -> uid
    | None -> Uid.gen ?g () in
  let msg1 = { sender= uid; ephemeral; static; timestamp } in
  Ok (Initiator { _Hi; _Ci; uid; remote; consumed= Atomic.make false; _Ei_priv }, msg1)

let msg1_to_string ~now (Initiator { uid; remote; _ }) { ephemeral; static; timestamp; _ } =
  let pkt = Bytes.make (1 + 3 + 4 + 32 + 48 + 28 + 16 + 16) '\000' in
  Bytes.set_uint8 pkt 0 1;
  Bytes.set_int32_le pkt 4 (uid :> int32);
  Bytes.blit_string ephemeral 0 pkt 8 32;
  Bytes.blit_string static 0 pkt 40 48;
  Bytes.blit_string timestamp 0 pkt 88 28;
  add_macs ~now remote ~off:116 pkt;
  Bytes.unsafe_to_string pkt

let tau bakery ~now addr =
  _mac ~key:(Bakery.secret bakery ~now) (Addr.to_octets addr)

let verify_mac ~key ~off pkt =
  let expect = _mac ~key pkt ~off:0 ~len:off in
  let have = String.sub pkt off 16 in
  Eqaf.equal expect have

let cookie ?g (bakery : Bakery.t) ~tau str =
  let pkt = Bytes.make 64 '\000' in
  Bytes.set_uint8 pkt 0 3;
  Bytes.blit_string str 4 pkt 4 4;
  let nonce = Mirage_crypto_rng.generate ?g 24 in
  Bytes.blit_string nonce 0 pkt 8 24;
  let adata = String.sub str (String.length str - 32) 16 in
  let s = xaead ~key:bakery.cookie_key ~nonce ~adata tau in
  Bytes.blit_string s 0 pkt 32 32;
  Bytes.unsafe_to_string pkt

let defend ?g (bakery : Bakery.t) limiter ~now ~load ~peer ~off pkt =
  let* () = guard ~err:(msgf "Invalid MAC1") @@ fun () ->
    verify_mac ~key:bakery.mac1_key ~off pkt in
  if not load then Ok `Ok
  else
    let tau = tau bakery ~now peer in
    if not (verify_mac ~key:tau ~off:(off + 16) pkt)
    then Ok (`Cookie (cookie ?g bakery ~tau pkt))
    else if not (Limiter.allow limiter ~now peer)
    then error_msgf "Too many retries"
    else Ok `Ok

let msg1_of_string ?g bakery limiter ~now ~load ~peer pkt =
  let* () = guard ~err:(msgf "Truncated msg1 packet") @@ fun () ->
    String.length pkt = 148 in
  let* () = guard ~err:(msgf "Invalid msg1 packet") @@ fun () ->
    String.get_int32_le pkt 0 = 1l in
  let* continue = defend ?g bakery limiter ~now ~load ~peer ~off:116 pkt in
  match continue with
  | `Cookie _ as cookie -> Ok cookie
  | `Ok ->
    let uid = String.get_int32_le pkt 4 in
    let uid = Uid.unsafe_of_int32 uid in
    let ephemeral = String.sub pkt 8 32 in
    let static = String.sub pkt 40 48 in
    let timestamp = String.sub pkt 88 28 in
    Ok (`Msg1 { sender= uid; ephemeral; static; timestamp; })

type msg2 =
  { sender : Uid.t
  ; receiver : Uid.t
  ; ephemeral : string
  ; empty : string }

let step1 ?g ?uid ~peer { sender= remote_uid; ephemeral= _Ei_pub; static; timestamp; } (_Sr_priv, (_Sr_pub, _)) =
  let open Digestif in
  let _Cr = BLAKE2S.digest_string "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" in
  let _Hr = mix _Cr "WireGuard v1 zx2c4 Jason@zx2c4.com" in
  let _Cr = BLAKE2S.to_raw_string _Cr in
  let _Hr = mix _Hr _Sr_pub in
  (* *)
  let _Cr = kdf1 ~ck:_Cr ~ikm:_Ei_pub in
  let _Hr = mix _Hr _Ei_pub in
  let* _SE = dh _Sr_priv _Ei_pub in (* _SE *)
  let _Cr, _k = kdf2 ~ck:_Cr ~ikm:_SE in
  let* _Si_pub = decrypt _k static _Hr in
  let _Hr = mix _Hr static in
  let* remote, _ts', set = match peer (public_of_octets _Si_pub) with
    | `Accept (remote, _ts', set) -> Ok (remote, _ts', set)
    | `Reject -> error_msgf "Unknown peer" in
  let* () = guard ~err:(msgf "Mismatched peer") @@ fun () ->
    Eqaf.equal remote.octets _Si_pub in
  let { _SS; _Q; _ } = remote in
  let _Cr, _k = kdf2 ~ck:_Cr ~ikm:_SS in
  let* _ts = decrypt _k timestamp _Hr in
  let _Hr = mix _Hr timestamp in
  let* () = guard ~err:(msgf "Replayed peer") @@ fun () ->
    let ok = match _ts' with
      | None -> true
      | Some _ts' -> newer _ts _ts' in
    if ok then set _ts; ok in
  (* (Er_priv, Er_pub) := DH-Generate() *)
  let _Er_priv, _Er_pub = Mirage_crypto_ec.X25519.gen_key ?g () in
  (* Cr := Kdf1(Cr, Er_pub) *)
  let _Cr = kdf1 ~ck:_Cr ~ikm:_Er_pub in
  (* msg.ephemeral := Er_pub *)
  let ephemeral = _Er_pub in
  (* Hr := Hash(Hr || msg.ephemeral) *)
  let _Hr = mix _Hr ephemeral in
  (* Cr := kdf1(Cr, DH(Er_priv, Ei_pub)) *)
  let* _EE = dh _Er_priv _Ei_pub in
  let _Cr = kdf1 ~ck:_Cr ~ikm:_EE in
  (* Cr := kdf1(Cr, DH(Er_priv, Si_pub)) *)
  let* _ES = dh _Er_priv _Si_pub in
  let _Cr = kdf1 ~ck:_Cr ~ikm:_ES  in
  (* (Cr, t, k) := Kdf3(Cr, Q) *)
  let _Cr, _t, _k = kdf3 ~ck:_Cr ~ikm:_Q in
  (* Hr := Hash(Hr || t) *)
  let _Hr = mix _Hr _t in
  (* msg.empty := Aead(k, 0, ε, Hr) *)
  let empty = aead _k "" _Hr in
  (* Hr := Hash(Hr || msg.empty) *)
  let _Hr = mix _Hr empty in
  let uid = match uid with
    | Some uid -> uid
    | None -> Uid.gen ?g () in
  let msg2 = { sender= uid; receiver= remote_uid; ephemeral; empty } in
  Ok (Responder { _Hr; _Cr; uid; remote_uid; remote; consumed= Atomic.make false; _Er_priv }, msg2)

let msg2_to_string
  : type a. now:int -> (responder, a) handshake -> msg2 -> string
  = fun ~now (Responder { remote; _ }) { sender; receiver; ephemeral; empty; _ } ->
  (* TODO(dinosaure): check uids from our [state] and [msg2]. *)
  let pkt = Bytes.make (1 + 3 + 4 + 4 + 32 + 16 + 16 + 16) '\000' in
  Bytes.set_uint8 pkt 0 2;
  Bytes.set_int32_le pkt 4 (sender :> int32);
  Bytes.set_int32_le pkt 8 (receiver :> int32);
  Bytes.blit_string ephemeral 0 pkt 12 32;
  Bytes.blit_string empty 0 pkt 44 16;
  add_macs ~now remote ~off:60 pkt;
  Bytes.unsafe_to_string pkt

let msg2_of_string ?g bakery limiter ~now ~load ~peer pkt =
  let* () = guard ~err:(msgf "Truncated msg2 packet") @@ fun () ->
    String.length pkt = 92 in
  let* () = guard ~err:(msgf "Invalid msg2 packet") @@ fun () ->
    String.get_int32_le pkt 0 = 2l in
  let* continue = defend ?g bakery limiter ~now ~load ~peer ~off:60 pkt in
  match continue with
  | `Cookie _ as cookie -> Ok cookie
  | `Ok ->
    let uid0 = String.get_int32_le pkt 4 in
    let sender = Uid.unsafe_of_int32 uid0 in
    let uid1 = String.get_int32_le pkt 8 in
    let receiver = Uid.unsafe_of_int32 uid1 in
    let ephemeral = String.sub pkt 12 32 in
    let empty = String.sub pkt 44 16 in
    Ok (`Msg2 ({ sender; receiver; ephemeral; empty }))

type keys = { send : string; recv : string }
type window = Window.t

type 'role role =
  | Initiator : initiator role
  | Responder : responder role

let is_initiator : type r. r role -> bool = function
  | Initiator -> true
  | Responder -> false

type ('role, 'state) session =
  { local : Uid.t
  ; remote : Uid.t
  ; keys : keys
  ; birth : int
  ; role : 'role role
  ; counter : int64 ref
  ; window : window
  ; confirmed : bool Atomic.t }

let uid_of_local { local; _ } = local
let uid_of_peer { remote; _ } = remote
let role : type r. (r, _) session -> r role = fun { role; _ } -> role

let session : type r. now:int -> role:r role -> local:Uid.t -> remote:Uid.t -> string -> (r, _) session
  = fun ~now ~role ~local ~remote _C ->
  let keys = match role with
    | Initiator -> let send, recv = kdf2 ~ck:_C ~ikm:"" in { send; recv }
    | Responder -> let recv, send = kdf2 ~ck:_C ~ikm:"" in { send; recv } in
  { local; remote; keys; birth= now
  ; role; counter= ref 0L; window= Window.make ()
  ; confirmed= Atomic.make (is_initiator role) }

let step2 ~now { sender; receiver; ephemeral= _Er_pub; empty } (_Si_priv, _Si_pub)
  (Initiator { _Ci; _Hi; uid; remote= { _Q; _ }; consumed; _Ei_priv } : (initiator, _) handshake) =
  let* () = guard ~err:(msgf "Handshake already consumed") @@ fun () ->
    not (Atomic.get consumed) in
  let* () = guard ~err:(msgf "Unexpected receiver UID") @@ fun () ->
    receiver = uid in
  let _Ci = kdf1 ~ck:_Ci ~ikm:_Er_pub in
  let _Hi = mix _Hi _Er_pub in
  let* _EE = dh _Ei_priv _Er_pub in
  let _Ci = kdf1 ~ck:_Ci ~ikm:_EE in
  let* _SE = dh _Si_priv _Er_pub in
  let _Ci = kdf1 ~ck:_Ci ~ikm:_SE in
  let _Ci, _t, _k = kdf3 ~ck:_Ci ~ikm:_Q in
  let _Hi = mix _Hi _t in
  let* _ = decrypt _k empty _Hi in
  (* let _Hi = mix _Hi empty in *)
  let* () = guard ~err:(msgf "Handshake already consumed") @@ fun () ->
    Atomic.compare_and_set consumed false true in
  Ok (session ~now ~role:Initiator ~local:receiver ~remote:sender _Ci)

let session_of_responder ~now
  (Responder { _Cr; uid; remote_uid; consumed; _ } : (responder, _) handshake) =
  let* () = guard ~err:(msgf "Handshake already consumed") @@ fun () ->
    Atomic.compare_and_set consumed false true in
  Ok (session ~now ~role:Responder ~local:uid ~remote:remote_uid _Cr)

let _REJECT_AFTER_MESSAGES = 0xffffffffffffdfffL
let _REJECT_AFTER_TIME = 180_000_000_000

let nonce counter =
  let buf = Bytes.make 12 '\000' in
  Bytes.set_int64_le buf 4 counter;
  Bytes.unsafe_to_string buf

let encrypt_data ~key ~counter msg =
  let key = Mirage_crypto.Chacha20.of_secret key in
  Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce:(nonce counter) msg

let decrypt_data ~key ~counter txt =
  let key = Mirage_crypto.Chacha20.of_secret key in
  Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce:(nonce counter) txt

type out =
  [ `Keepalive
  | `Data of string ]

let recv ~now { local; keys; birth; window; _ } pkt =
  let* () = guard ~err:(msgf "Truncated data packet") @@ fun () ->
    String.length pkt >= 32 in
  let* () = guard ~err:(msgf "Invalid data packet") @@ fun () ->
    String.get_int32_le pkt 0 = 4l in
  let* () = guard ~err:(msgf "Unexpected receiver uid") @@ fun () ->
    String.get_int32_le pkt 4 = (local :> int32) in
  let* () = guard ~err:(msgf "Expired session") @@ fun () ->
    now - birth < _REJECT_AFTER_TIME in
  let counter = String.get_int64_le pkt 8 in
  let* () = guard ~err:(msgf "Exhausted session") @@ fun () ->
    Int64.unsigned_compare counter _REJECT_AFTER_MESSAGES < 0 in
  let txt = String.sub pkt 16 (String.length pkt - 16) in
  let* msg = match decrypt_data ~key:keys.recv ~counter txt with
    | Some msg -> Ok msg
    | None -> error_msgf "AEAD authentication failed" in
  let* () = guard ~err:(msgf "Replayed packet") @@ fun () ->
    Window.validate window counter in
  if String.length msg = 0 then Ok `Keepalive else Ok (`Data msg)

let confirm ~now session pkt =
  let* data = recv ~now session pkt in
  let* () = guard ~err:(msgf "Session already confirmed") @@ fun () ->
    Atomic.compare_and_set session.confirmed false true in
  Ok ({ session with confirmed= session.confirmed }, data)

let _PADDING = 16

let send ~now ({ remote; keys; birth; _ } as session) msg =
  let* () = guard ~err:(msgf "Expired session") @@ fun () ->
    now - birth < _REJECT_AFTER_TIME in
  let counter = !(session.counter) in
  let* () = guard ~err:(msgf "Exhausted session") @@ fun () ->
    Int64.unsigned_compare counter _REJECT_AFTER_MESSAGES < 0 in
  session.counter := Int64.add counter 1L;
  let len = String.length msg in
  let pad = (_PADDING - (len mod _PADDING)) land (_PADDING - 1) in
  let buf = Bytes.make (len + pad) '\000' in
  Bytes.blit_string msg 0 buf 0 len;
  let txt = encrypt_data ~key:keys.send ~counter (Bytes.unsafe_to_string buf) in
  let pkt = Bytes.make (16 + String.length txt) '\000' in
  (* TODO(dinosaure): use authenticate_encrypt_into *)
  Bytes.set_uint8 pkt 0 4;
  Bytes.set_int32_le pkt 4 (remote :> int32);
  Bytes.set_int64_le pkt 8 counter;
  Bytes.blit_string txt 0 pkt 16 (String.length txt);
  Ok (Bytes.unsafe_to_string pkt)

let keepalive ~now session = send ~now session String.empty

let expired ~now { birth; counter; _ } =
  now () - birth >= _REJECT_AFTER_TIME
  || Int64.unsigned_compare !counter _REJECT_AFTER_MESSAGES >= 0

let _REKEY_AFTER_MESSAGES = 0x1000000000000000L
let _REKEY_AFTER_TIME = 120_000_000_000
let _REKEY_TIMEOUT = 5_000_000_000
let _KEEPALIVE_TIMEOUT = 10_000_000_000

let rekey_on_send ~now { birth; counter; role; _ } =
  Int64.unsigned_compare !counter _REKEY_AFTER_MESSAGES >= 0
  || (is_initiator role && now () - birth >= _REKEY_AFTER_TIME)

let rekey_on_recv ~now ({ birth; _ } : (initiator, _) session) =
  now () - birth >= _REJECT_AFTER_TIME - _KEEPALIVE_TIMEOUT - _REKEY_TIMEOUT

let keys { keys; _ } = keys

(*
let run () =
  Mirage_crypto_rng_unix.use_default ();
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  let _Si = Mirage_crypto_ec.X25519.gen_key () in
  let _Sr = Mirage_crypto_ec.X25519.gen_key () in
  let _Kr =
    let open Digestif in
    let ctx = BLAKE2S.hmac_init ~key:"mac1----" in
    let ctx = BLAKE2S.hmac_feed_string ctx (snd _Sr) in
    BLAKE2S.hmac_get ctx |> BLAKE2S.to_raw_string in
  let _Q = String.make 32 '\000' in
  let* initiator, (ephemeral, static, timestamp) =
    step0 ~now _Si (snd _Sr) in
  let* Responder { _Cr; _ }, (ephemeral, empty) =
    step1 _Q (ephemeral, static, timestamp) _Sr in
  let* Initiator { _Ci; _ } = step2 _Q (ephemeral, empty) _Si initiator in
  (* (Ti_send == Tr_recv, Ti_recv == Tr_send) := Kdf2(Ci == Cr, ε) *)
  let _T_send_i, _T_recv_i = kdf2 ~ck:_Ci ~ikm:"" in
  let _T_recv_r, _T_send_r = kdf2 ~ck:_Cr ~ikm:"" in
  Ok ()
*)
