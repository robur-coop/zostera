(** Zostera, a pure implementation of the Wireguard protocol.

    This module implements the Wireguard protocol which is described here:
    https://www.wireguard.com/papers/wireguard.pdf
*)

type error = [ `Msg of string | `Invalid_cookie | Mirage_crypto_ec.error ]
(** Error returned by the handshake steps and the packet decoders. The only
    thing to do in the event of an error is to {i drop} the current operation
    (drop packets and cancel handshakes). *)

val pp_error : error Fmt.t

type uid = private int32

val uid : ?g:Mirage_crypto_rng.g -> unit -> uid

type psk

val psk : string -> psk

(** {1 Identities.} *)

type t
(** A local static identity: an X25519 secret with its public part and its
    precomputed {i mac1}. This is what a Wireguard {i node} {e is}. *)

type public
(** A static public key and its precomputed {i mac1}. *)

val gen : ?g:Mirage_crypto_rng.g -> unit -> t
(** [gen ?g ()] generates a new identity. *)

val public_of_octets : string -> public
(** [public_of_octets raw] is a peer's public key from its 32 raw bytes. Note
    that every 32-byte string is a {i valid} X25519 public key. Low-order points
    are rejected by the key exchange.

    @raise Invalid_argument if [raw] is not 32 bytes. *)

val octets_of_public : public -> string
(** [octets_of_public pub] is the 32-byte encoding, suitable for a peer
    registry. *)

val public : t -> public
(** [public t] is the public key from the given identity [t]. *)

type remote

val remote : ?psk:psk -> t -> public -> (remote, [> error ]) result
val remote_of_octets : ?psk:psk -> t -> string -> (remote, [> error ]) result
val octets_of_remote : remote -> string
val consume_cookie : remote -> now:(unit -> int) -> uid:uid -> string -> (unit, [> error ]) result

(** {2 Cookies.} *)

module Bakery : sig
  type identity = t
  type t

  val create : ?g:Mirage_crypto_rng.g -> me:identity -> unit -> t
end

module Addr = Addr
module Limiter = Limiter

type timestamp

val newer : timestamp -> timestamp -> bool

type initiator
type responder

type pending
type confirmed

type ('a, 'state) handshake

val uid_of_initiator : (initiator, pending) handshake -> uid

type msg1

val step0 :
     ?g:Mirage_crypto_rng.g
  -> now:(unit -> int)
  -> t
  -> remote
  -> ((initiator, pending) handshake * msg1, [> error ]) result

val pkt_of_initiator :
     now:(unit -> int)
  -> (initiator, pending) handshake
  -> msg1
  -> string

val msg1_of_string :
     ?g:Mirage_crypto_rng.g
  -> Bakery.t
  -> Limiter.t
  -> now:(unit -> int)
  -> load:bool
  -> peer:Addr.t
  -> string
  -> ([ `Msg1 of uid * msg1 | `Cookie of string ], [> `Msg of string ]) result

type msg2

val step1 :
     ?g:Mirage_crypto_rng.g
  -> peer:(public -> [ `Accept of remote * (timestamp -> bool)
                     | `Reject ])
  -> msg1
  -> t
  -> ((responder, confirmed) handshake * msg2, [> error ]) result

val pkt_of_responder :
     now:(unit -> int)
  -> (responder, 'a) handshake
  -> uid
  -> msg2
  -> string

type link

val msg2_of_string :
     ?g:Mirage_crypto_rng.g
  -> Bakery.t
  -> Limiter.t
  -> now:(unit -> int)
  -> load:bool
  -> peer:Addr.t
  -> string
  -> ([ `Msg2 of link * msg2 | `Cookie of string ], [> `Msg of string ]) result

type ('a, 'state) session

val step2 :
     now:(unit -> int)
  -> link
  -> msg2
  -> t
  -> (initiator, pending) handshake
  -> ((initiator, confirmed) session, [> error ]) result

val session_of_responder :
     now:(unit -> int)
  -> uid
  -> (responder, confirmed) handshake
  -> ((responder, pending) session, [> error ]) result

val confirm : (responder, pending) session -> string -> ((responder, confirmed) session, [> error ]) result

type keys = { send : string; recv : string }

val keys : ('role, 'state) session -> keys

(**/*)

val tai64n : now:(unit -> int) -> string
(** See https://cr.yp.to/libtai/tai64.html.
    We have 10 years before the world ends. *)
