type sym =
  { _Hi : Digestif.BLAKE2S.t
  ; _Ci : string
  ; _Ei_priv : Mirage_crypto_ec.X25519.priv }

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
  Bytes.set_int64_be 0 secs;
  Bytes.set_int32_be 8 tai;
  Bytes.unsafe_to_string buf

module Kdf = Hkdf.Make (Digestif.BLAKE2S)

let kdf1 ~ck ~ikm =
  let prk = Kdf.extract ~salt:ck ikm in
  let info = "\x01" in
  Kfd.expand ~prk ~info 32 in

let kdf2 ~ck ~ikm =
  let prk = Kdf.extract ~salt:ck ikm in
  let info = "\x01" in
  let ck' = Kdf.expand ~prk ~info 32 in
  let info = ck' ^ "\x02" in
  let k = Kdf.expand ~prk ~info 32 in
  (ck', k)

let dh priv pub =
  Mirage_crypto_ec.X25519.key_exchange priv pub

let aead _k ?(nonce= String.make 12 '\000') txt _Hi =
  let key = Mirage_crypto.Chacha20.of_secret _k in
  let adata = Digestif.BLAKE2S.to_raw_string _Hi in
  Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ~adata txt

(* Si => it's us
   Sr => it's our peer *)
let sym ?g ~now (_Si_priv, _Si_pub) _Sr_pub =
  let open Digestif in
  (* Ci := Hash(Construction) *)
  let _Ci = BLAKE2S.digest_string "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" in
  (* Hi := Hash(Ci || Identifier) *)
  let _Hi = mix _Ci "WireGuard v1 zx2c4 Jason@zx2c4.com" in
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
  ({ _Hi; _Ci; _Ei_priv }, (ephemeral, statc, timestamp))

let make_ikpsk2_25519_ChaChaPoly_BLAKE2s = assert false

let init =
  (* | 0x1 | 0x0 | 0x0 | 0x0 |
     | sender := Ii          |
     | ephemeral             |
     | static                |
     | timestamp             |
     | mac1      | mac2      | *)
  let sender = Randomconv.int32 (Mirage_crypto_rng.generate ?g) in
  let pk, public = Mirage_crypto_ec.X25519.gen_key ?g () in
  let buf = Bytes.make (4 + 4 + 32 + 32 + 12 + 16 + 16) '\000' in
  Bytes.set_int32_le buf 4 sender;
  assert (String.length public = 32);
  Bytes.blit_string public 0 buf 8 (String.length public);
  Bytes.blit_string t.public 0 bu
