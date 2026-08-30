(** Zostera, a pure implementation of the Wireguard protocol.

    This module implements the Wireguard protocol which is described here:
    https://www.wireguard.com/papers/wireguard.pdf
*)

type error = [ `Msg of string | Mirage_crypto_ec.error ]

val pp_error : error Fmt.t

type uid = private int32

val uid : ?g:Mirage_crypto_rng.g -> unit -> uid

type limiter

val limiter : unit -> limiter

type initiator
type responder

type unverified
type verified

type ('a, 'state) handshake

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

val cookie_of_pkt : validator -> now:(unit -> int) -> uid:uid -> mac1:mac1 -> string -> bool
val cookie_of_validator : validator -> now:(unit -> int) -> cookie option

val step0 :
     ?g:Mirage_crypto_rng.g
  -> now:(unit -> int)
  -> t
  -> public
  -> ((initiator, unverified) handshake * msg1, [> error ]) result

val pkt_of_initiator :
     (initiator, unverified) handshake
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
  -> ([ `Msg1 of uid * msg1 | `Cookie of string ], [> `Msg of string ]) result

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
  -> public
  -> ?cookie:cookie
  -> msg2
  -> mac1 * string

type link

val msg2_of_string :
     ?g:Mirage_crypto_rng.g
  -> checker
  -> limiter
  -> now:(unit -> int)
  -> load:bool
  -> peer:addr
  -> string
  -> ([ `Msg2 of link * msg2 | `Cookie of string ], [> `Msg of string ]) result

type session

val step2 :
     ?psk:psk
  -> now:(unit -> int)
  -> link
  -> msg2
  -> t
  -> (initiator, unverified) handshake
  -> (session, [> error ]) result

val session_of_responder :
     now:(unit -> int)
  -> uid
  -> (responder, verified) handshake
  -> session

type keys = { send : string; recv : string }

val keys : session -> keys
