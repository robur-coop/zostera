type uid = private int32

type initiator
type responder

type unverified
type verified

type ('a, 'state) handshake

type error =
  [ `Msg of string | Mirage_crypto_ec.error ]

val pp_error : error Fmt.t

type psk
type cookie

val psk : string -> psk
val cookie : string -> cookie

type secret
type public

val gen : ?g:Mirage_crypto_rng.g -> unit -> secret * public

type msg1

val step0 :
     ?g:Mirage_crypto_rng.g
  -> now:(unit -> int)
  -> (secret * public)
  -> public
  -> ((initiator, unverified) handshake * msg1, [> error ]) result

type msg2

val step1 :
     ?g:Mirage_crypto_rng.g
  -> ?psk:psk
  -> msg1
  -> (secret * public)
  -> ((responder, verified) handshake * msg2, [> error ]) result

val step2 :
     ?psk:psk
  -> msg2
  -> (secret * public)
  -> (initiator, 'a) handshake
  -> ((initiator, verified) handshake, [> error ]) result

val pkt_of_initiator :
     (initiator, unverified) handshake
  -> uid
  -> public
  -> ?cookie:cookie
  -> msg1
  -> string

val pkt_of_responder :
     (responder, 'a) handshake
  -> uid
  -> uid
  -> public
  -> ?cookie:cookie
  -> msg2
  -> string

val keys : ('a, verified) handshake -> string * string
