type initiator = Initiator
type responder = Responder

type 'a sym =
  | Initiator : { _Hi : Digestif.BLAKE2S.t
    ; _Ci : string
    ; _Ei_priv : Mirage_crypto_ec.X25519.secret } -> initiator sym
  | Responder : { _Hr : Digestif.BLAKE2S.t
    ; _Cr : string
    ; _Er_priv : Mirage_crypto_ec.X25519.secret } -> responder sym

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
  Mirage_crypto_ec.X25519.key_exchange priv pub
  |> Result.map_error (Fmt.str "%a" Mirage_crypto_ec.pp_error)
  |> Result.error_to_failure

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
  | Some plain -> plain
  | None -> failwith "buit: AEAD authentication failed"

let step0 ?g ~now (_Si_priv, _Si_pub) _Sr_pub =
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
  let _Ci, _k = kdf2 ~ck:_Ci ~ikm:(dh _Ei_priv _Sr_pub) in
  (* msg.static := Aead(k, 0, Si_pub, Hi) *)
  let static = aead _k _Si_pub _Hi in
  (* Hi := Hash(Hi || msg.static) *)
  let _Hi = mix _Hi static in
  (* (Ci, k) := Kdf2(Ci, DH(Si_priv, Sr_pub) *)
  let _Ci, _k = kdf2 ~ck:_Ci ~ikm:(dh _Si_priv _Sr_pub) in
  (* msg.timestamp := Aead(k, 0, Timestamp(), Hi) *)
  let timestamp = aead _k (tai64n ~now) _Hi in
  (* Hi := Hash(Hi || msg.timestamp) *)
  let _Hi = mix _Hi timestamp in
  (Initiator { _Hi; _Ci; _Ei_priv }, (ephemeral, static, timestamp))

let step1 ?g _Q (_Ei_pub, static, timestamp) (_Sr_priv, _Sr_pub) =
  let open Digestif in
  let _Cr = BLAKE2S.digest_string "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" in
  let _Hr = mix _Cr "WireGuard v1 zx2c4 Jason@zx2c4.com" in
  let _Cr = BLAKE2S.to_raw_string _Cr in
  let _Hr = mix _Hr _Sr_pub in
  (* *)
  let _Cr = kdf1 ~ck:_Cr ~ikm:_Ei_pub in
  let _Hr = mix _Hr _Ei_pub in
  let _Cr, _k = kdf2 ~ck:_Cr ~ikm:(dh _Sr_priv _Ei_pub) in
  let _Si_pub = decrypt _k static _Hr in
  let _Hr = mix _Hr static in
  let _Cr, _k = kdf2 ~ck:_Cr ~ikm:(dh _Sr_priv _Si_pub) in
  let _t = decrypt _k timestamp _Hr in
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
  let _Cr = kdf1 ~ck:_Cr ~ikm:(dh _Er_priv _Ei_pub) in
  (* Cr := kdf1(Cr, DH(Er_priv, Si_pub)) *)
  let _Cr = kdf1 ~ck:_Cr ~ikm:(dh _Er_priv _Si_pub) in
  (* (Cr, t, k) := Kdf3(Cr, Q) *)
  let _Cr, _t, _k = kdf3 ~ck:_Cr ~ikm:_Q in
  (* Hr := Hash(Hr || t) *)
  let _Hr = mix _Hr _t in
  (* msg.empty := Aead(k, 0, ε, Hr) *)
  let empty = aead _k "" _Hr in
  (* Hr := Hash(Hr || msg.empty) *)
  let _Hr = mix _Hr empty in
  (Responder { _Hr; _Cr; _Er_priv }, (ephemeral, empty))

let step2 _Q (_Er_pub, empty) (_Si_priv, _Si_pub) (Initiator { _Ci; _Hi; _Ei_priv }) =
  let _Ci = kdf1 ~ck:_Ci ~ikm:_Er_pub in
  let _Hi = mix _Hi _Er_pub in
  let _Ci = kdf1 ~ck:_Ci ~ikm:(dh _Ei_priv _Er_pub) in
  let _Ci = kdf1 ~ck:_Ci ~ikm:(dh _Si_priv _Er_pub) in
  let _Ci, _t, _k = kdf3 ~ck:_Ci ~ikm:_Q in
  let _Hi = mix _Hi _t in
  let _ = decrypt _k empty _Hi in
  let _Hi = mix _Hi empty in
  Initiator { _Hi; _Ci; _Ei_priv }

let run () =
  Mirage_crypto_rng_unix.use_default ();
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  let _Si = Mirage_crypto_ec.X25519.gen_key () in
  let _Sr = Mirage_crypto_ec.X25519.gen_key () in
  let _Q = String.make 32 '\000' in
  let initiator, (ephemeral, static, timestamp) =
    step0 ~now _Si (snd _Sr) in
  let Responder { _Cr; _ }, (ephemeral, empty) =
    step1 _Q (ephemeral, static, timestamp) _Sr in
  let Initiator { _Ci; _ } = step2 _Q (ephemeral, empty) _Si initiator in
  Fmt.pr ">>> Ci: %s\n%!" (Ohex.encode _Ci);
  Fmt.pr ">>> Cr: %s\n%!" (Ohex.encode _Cr);
  print_endline "Handshake: ok"
