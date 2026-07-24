[@@@warning "-37"]

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( let* ) = Result.bind

type error =
  [ `Msg of string | Mirage_crypto_ec.error ]

let pp_error ppf = function
  | #Mirage_crypto_ec.error as err -> Mirage_crypto_ec.pp_error ppf err
  | `Msg msg -> Fmt.string ppf msg

type uid = int32

type initiator = Initiator
type responder = Responder

type unverified = |
type verified = |

type ('a, 'state) handshake =
  | Initiator : { _Hi : Digestif.BLAKE2S.t
    ; _Ci : string
    ; _Ei_priv : Mirage_crypto_ec.X25519.secret } -> (initiator, 'state) handshake
  | Responder : { _Hr : Digestif.BLAKE2S.t
    ; _Cr : string
    ; _Er_priv : Mirage_crypto_ec.X25519.secret } -> (responder, verified) handshake

type psk = string
type cookie = string

let _Q = String.make 32 '\000'

let psk str =
  if String.length str <> 32 then invalid_arg "Bruit.psk: invalid private shared key";
  str

let cookie str =
  if String.length str <> 16 then invalid_arg "Bruit.cookie: invalid cookie";
  str

type secret = Mirage_crypto_ec.X25519.secret
type public = string * string

let gen ?g () : secret * public =
  let secret, public = Mirage_crypto_ec.X25519.gen_key ?g () in
  let open Digestif in
  let ctx = BLAKE2S.hmac_init ~key:"mac1----" in
  let ctx = BLAKE2S.hmac_feed_string ctx public in
  let _K = BLAKE2S.hmac_get ctx |> BLAKE2S.to_raw_string in
  (secret, (public, _K))

let mix hash str =
  let open Digestif in
  let ctx = BLAKE2S.empty in
  let ctx = BLAKE2S.feed_string ctx (BLAKE2S.to_raw_string hash) in
  let ctx = BLAKE2S.feed_string ctx str in
  BLAKE2S.get ctx

let tai64n ~now =
  let nsecs = Int64.of_int (now ()) in
  let secs = Int64.div nsecs 1_000_000_000L in
  let tai = Int64.rem nsecs 1_000_000_000L in
  let secs = Int64.add secs 0x400000000000000AL in
  let tai = Int64.to_int32 tai in
  let buf = Bytes.create 12 in
  Bytes.set_int64_be buf 0 secs;
  Bytes.set_int32_be buf 8 tai;
  Bytes.unsafe_to_string buf

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

let empty = String.make 16 '\x00'

let mac2 ?(off= 0) pkt = function
  | None -> Bytes.blit_string empty 0 pkt off 16
  | Some cookie ->
    let open Digestif in
    let _K = BLAKE2S.hmac_init ~key:"cookie--" in
    let _K = BLAKE2S.hmac_feed_string _K cookie in
    let _K = BLAKE2S.hmac_get _K |> BLAKE2S.to_raw_string in
    let ctx = BLAKE2S.hmac_init ~key:_K in
    let ctx = BLAKE2S.hmac_feed_bytes ctx pkt ~off:0 ~len:off in
    let mac2 = BLAKE2S.hmac_get ctx |> BLAKE2S.to_raw_string in
    Bytes.blit_string mac2 0 pkt off 16

type msg1 = string * string * string

let step0 ?g ~now (_Si_priv, (_Si_pub, _)) (_Sr_pub, _) =
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
  let* _SS = dh _Si_priv _Sr_pub in
  let _Ci, _k = kdf2 ~ck:_Ci ~ikm:_SS in
  (* msg.timestamp := Aead(k, 0, Timestamp(), Hi) *)
  let timestamp = aead _k (tai64n ~now) _Hi in
  (* Hi := Hash(Hi || msg.timestamp) *)
  let _Hi = mix _Hi timestamp in
  Ok (Initiator { _Hi; _Ci; _Ei_priv }, (ephemeral, static, timestamp))

let pkt_of_initiator (Initiator _) uid (_, _Kr) ?cookie (ephemeral, static, timestamp) =
  let pkt = Bytes.make (1 + 3 + 4 + 32 + 48 + 28 + 16 + 16) '\000' in
  Bytes.set_uint8 pkt 0 1;
  Bytes.set_int32_be pkt 4 uid;
  Bytes.blit_string ephemeral 0 pkt 8 32;
  Bytes.blit_string static 0 pkt 40 48;
  Bytes.blit_string timestamp 0 pkt 88 28;
  let open Digestif in
  let mac1 = BLAKE2S.hmac_init ~key:_Kr in
  let mac1 = BLAKE2S.hmac_feed_bytes mac1 pkt ~off:0 ~len:116 in
  let mac1 = BLAKE2S.hmac_get mac1 |> BLAKE2S.to_raw_string in
  Bytes.blit_string mac1 0 pkt 116 16;
  mac2 ~off:132 pkt cookie;
  Bytes.unsafe_to_string pkt

type msg2 = string * string

let step1 ?g ?psk:(_Q= _Q) (_Ei_pub, static, timestamp) (_Sr_priv, (_Sr_pub, _)) =
  let open Digestif in
  let _Cr = BLAKE2S.digest_string "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" in
  let _Hr = mix _Cr "WireGuard v1 zx2c4 Jason@zx2c4.com" in
  let _Cr = BLAKE2S.to_raw_string _Cr in
  let _Hr = mix _Hr _Sr_pub in
  (* *)
  let _Cr = kdf1 ~ck:_Cr ~ikm:_Ei_pub in
  let _Hr = mix _Hr _Ei_pub in
  let* _SE = dh _Sr_priv _Ei_pub in
  let _Cr, _k = kdf2 ~ck:_Cr ~ikm:_SE in
  let* _Si_pub = decrypt _k static _Hr in
  let _Hr = mix _Hr static in
  let* _SS = dh _Sr_priv _Si_pub in
  let _Cr, _k = kdf2 ~ck:_Cr ~ikm:_SS in
  let* _t = decrypt _k timestamp _Hr in
  let _Hr = mix _Hr timestamp in
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
  Ok (Responder { _Hr; _Cr; _Er_priv }, (ephemeral, empty))

let pkt_of_responder
  : type a. (responder, a) handshake -> uid -> uid -> public -> ?cookie:cookie -> msg2 -> string
  = fun (Responder _) uid0 uid1 (_, _Ki) ?cookie (ephemeral, empty) ->
  let pkt = Bytes.make (1 + 3 + 4 + 4 + 32 + 16 + 16 + 16) '\000' in
  Bytes.set_uint8 pkt 0 2;
  Bytes.set_int32_be pkt 4 uid0;
  Bytes.set_int32_be pkt 8 uid1;
  Bytes.blit_string ephemeral 0 pkt 12 32;
  Bytes.blit_string empty 0 pkt 44 16;
  let open Digestif in
  let mac1 = BLAKE2S.hmac_init ~key:_Ki in
  let mac1 = BLAKE2S.hmac_feed_bytes mac1 pkt ~off:0 ~len:60 in
  let mac1 = BLAKE2S.hmac_get mac1 |> BLAKE2S.to_raw_string in
  Bytes.blit_string mac1 0 pkt 60 16;
  mac2 ~off:76 pkt cookie;
  Bytes.unsafe_to_string pkt

let step2 ?psk:(_Q= _Q) (_Er_pub, empty) (_Si_priv, _Si_pub) (Initiator { _Ci; _Hi; _Ei_priv }) =
  let _Ci = kdf1 ~ck:_Ci ~ikm:_Er_pub in
  let _Hi = mix _Hi _Er_pub in
  let* _EE = dh _Ei_priv _Er_pub in
  let _Ci = kdf1 ~ck:_Ci ~ikm:_EE in
  let* _SE = dh _Si_priv _Er_pub in
  let _Ci = kdf1 ~ck:_Ci ~ikm:_SE in
  let _Ci, _t, _k = kdf3 ~ck:_Ci ~ikm:_Q in
  let _Hi = mix _Hi _t in
  let* _ = decrypt _k empty _Hi in
  let _Hi = mix _Hi empty in
  Ok (Initiator { _Hi; _Ci; _Ei_priv })

let keys : type a. (a, verified) handshake -> string * string = function
  | Initiator { _Ci; _ } -> kdf2 ~ck:_Ci ~ikm:""
  | Responder { _Cr; _ } -> kdf2 ~ck:_Cr ~ikm:""

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
