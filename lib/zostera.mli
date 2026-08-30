type uid = private int32

val uid : ?g:Mirage_crypto_rng.g -> unit -> uid

type limiter

val limiter : unit -> limiter

type initiator
type responder

type unverified
type verified

type ('a, 'state) handshake

type error =
  [ `Msg of string | Mirage_crypto_ec.error ]

val pp_error : error Fmt.t

type psk

val psk : string -> psk

type addr

val addr : Ipaddr.t -> port:int -> addr

type t
type public

val gen : ?g:Mirage_crypto_rng.g -> unit -> t
val public_of_octets : string -> public
val public : t -> public

type checker

val checker : ?g:Mirage_crypto_rng.g -> me:t -> unit -> checker

type validator

val validator : public -> validator

type msg1 and mac1
type cookie

val cookie_of_pkt : validator -> mac1:mac1 -> string -> cookie option

val step0 :
     ?g:Mirage_crypto_rng.g
  -> now:(unit -> int)
  -> t
  -> public
  -> ((initiator, unverified) handshake * msg1, [> error ]) result

val pkt_of_initiator :
     (initiator, unverified) handshake
  -> uid
  -> public
  -> ?cookie:cookie
  -> msg1
  -> mac1 * string

val msg1_of_string :
     ?g:Mirage_crypto_rng.g
  -> checker
  -> limiter
  -> now:(unit -> int)
  -> load:bool
  -> peer:addr
  -> string
  -> ([ `Msg1 of uid * msg1 | `Cookie of cookie ], [> `Msg of string ]) result

type msg2

val step1 :
     ?g:Mirage_crypto_rng.g
  -> ?psk:psk
  -> msg1
  -> t
  -> ((responder, verified) handshake * msg2, [> error ]) result

val pkt_of_responder :
     (responder, 'a) handshake
  -> uid
  -> uid
  -> public
  -> ?cookie:cookie
  -> msg2
  -> string

val msg2_of_string :
     ?cookie:cookie
  -> public
  -> string
  -> (uid * uid * msg2, [> `Msg of string ]) result

val step2 :
     ?psk:psk
  -> msg2
  -> t
  -> (initiator, 'a) handshake
  -> ((initiator, verified) handshake, [> error ]) result

type keys = { send : string; recv : string }

val keys : ('a, verified) handshake -> keys
