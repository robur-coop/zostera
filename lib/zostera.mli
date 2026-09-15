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

type mac1

(** {2 Cookies.} *)

type cookie_generator

val cookie_generator : ?g:Mirage_crypto_rng.g -> me:t -> unit -> cookie_generator

type validator

val validator : public -> validator

type cookie
(** To prevent denial of service attacks a peer may send back a cookie while
    under load. A [cookie] represents such a cookie. *)

val check_cookie_of_pkt :
     validator
  -> now:(unit -> int)
  -> uid:uid
  -> mac1:mac1
  -> string
  -> (cookie, [> error ]) result

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

type psk

val psk : string -> psk

type msg1

val step0 :
     ?g:Mirage_crypto_rng.g
  -> now:(unit -> int)
  -> t
  -> public
  -> ((initiator, pending) handshake * msg1, [> error ]) result

val pkt_of_initiator :
     (initiator, pending) handshake
  -> public
  -> ?cookie:cookie
  -> msg1
  -> mac1 * string

val msg1_of_string :
     ?g:Mirage_crypto_rng.g
  -> cookie_generator
  -> Limiter.t
  -> now:(unit -> int)
  -> load:bool
  -> peer:Addr.t
  -> string
  -> ([ `Msg1 of uid * msg1 | `Cookie of string ], [> `Msg of string ]) result

type msg2

val step1 :
     ?g:Mirage_crypto_rng.g
  -> peer:(public -> timestamp -> [ `Accept of psk option | `Reject ])
  -> msg1
  -> t
  -> ((responder, confirmed) handshake * msg2, [> error ]) result

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
  -> cookie_generator
  -> Limiter.t
  -> now:(unit -> int)
  -> load:bool
  -> peer:Addr.t
  -> string
  -> ([ `Msg2 of link * msg2 | `Cookie of string ], [> `Msg of string ]) result

type session

val step2 :
     ?psk:psk
  -> now:(unit -> int)
  -> link
  -> msg2
  -> t
  -> (initiator, pending) handshake
  -> (session, [> error ]) result

val session_of_responder :
     now:(unit -> int)
  -> uid
  -> (responder, confirmed) handshake
  -> session

type keys = { send : string; recv : string }

val keys : session -> keys

(**/*)

val tai64n : now:(unit -> int) -> string
(** See https://cr.yp.to/libtai/tai64.html.
    We have 10 years before the world ends. *)
