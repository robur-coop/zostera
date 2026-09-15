(** Zostera, a pure implementation of the Wireguard protocol.

    This module implements the Wireguard protocol which is described here:
    https://www.wireguard.com/papers/wireguard.pdf
*)

type error = [ `Msg of string | `Invalid_cookie | Mirage_crypto_ec.error ]
(** Error returned by the handshake steps and the packet decoders. The only
    thing to do in the event of an error is to {i drop} the current operation
    (drop packets and cancel handshakes). *)

val pp_error : error Fmt.t
(** Pretty printer for {!type:error} values. *)

type uid = private int32

val uid : ?g:Mirage_crypto_rng.g -> unit -> uid

type psk

val psk : string -> psk

(** {2 Identity.} *)

type t
(** A local static identity: an X25519 secret with its public part and some 
    precomputed values. *)

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

(** {2 Remote identity.} *)

type remote
(** A remote static identity: an X25519 public and some precomputed values with
    the local identity we use. *)

val remote : ?psk:psk -> t -> public -> (remote, [> error ]) result
(** [remote ?psk my_own_identity public] returns a remote identity according to
    its public key and our identity. *)

val remote_of_octets : ?psk:psk -> t -> string -> (remote, [> error ]) result
(** [remote_of_octets ?psk my_own_identity str] returns a remote identity
    according to its public key in the serialized form and our identity. *)

val octets_of_remote : remote -> string
(** [octets_of_remote remote] returns the serialized form of the remote
    identity's public key. *)

val consume_cookie :
     remote
  -> now:(unit -> int)
  -> uid:uid
  -> string
  -> (unit, [> error ]) result
(** [consume_cookie remote ~now ~uid pkt] validates the received cookie from
    the given [remote] (with its [uid] according to the current handshake, see
    {!val:uid_of_initiator}). *)

(** {2 Bakery of cookies.} *)

module Bakery : sig
  type identity = t
  type t

  val create : ?g:Mirage_crypto_rng.g -> me:identity -> unit -> t
end

module Addr = Addr
module Limiter = Limiter

type timestamp
(** Type of timestamps. *)

val newer : timestamp -> timestamp -> bool
(** [newer t0 t1] returns [true] if [t0 < t1]. Otherwise, it returns [false]. *)

type initiator
type responder

type pending
type confirmed

type ('role, 'state) handshake

val uid_of_initiator : (initiator, pending) handshake -> uid

type msg1
(** Type of the first message that an {i initiator} should send to the
    {i responder}. *)

val step0 :
     ?g:Mirage_crypto_rng.g
  -> now:(unit -> int)
  -> t
  -> remote
  -> ((initiator, pending) handshake * msg1, [> error ]) result
(** [step0 ?g ~now identity remote] generates a new handshake state and a
    {!type:msg1} that's the user can send to the {i responder}. *)

val pkt_of_initiator :
     now:(unit -> int)
  -> (initiator, pending) handshake
  -> msg1
  -> string
(** [pkt_of_initiator ~now state msg1] returns a WireGuard packet which should
    be send to the {i responder}. *)

val msg1_of_string :
     ?g:Mirage_crypto_rng.g
  -> Bakery.t
  -> Limiter.t
  -> now:(unit -> int)
  -> load:bool
  -> peer:Addr.t
  -> string
  -> ([ `Msg1 of msg1 | `Cookie of string ], [> `Msg of string ]) result
(** [msg1_of_string ?g bakery limiter ~now ~load ~peer pkt] tries to parse the
    given packet [pkt] from the given [peer] and extract a {!type:msg1} value.
    If the user is under an heavy load, [load] can be set to [true] and
    [msg1_of_string] generates a cookie to send back to the given [peer]. *)

type msg2
(** Type of the second message that an {i responder} should send back to the
    {i initiator}. *)

val step1 :
     ?g:Mirage_crypto_rng.g
  -> peer:(public -> [ `Accept of remote * timestamp option * (timestamp -> unit)
                     | `Reject ])
  -> msg1
  -> t
  -> ((responder, confirmed) handshake * msg2, [> error ]) result
(** [step1 ?g ~peer msg1 identity] returns a new handshake state and a
    {!type:msg2} value. [peer] lets the user to accept or reject the
    {i initiator}. When the user would like to accept a new {i initiator}, it
    must return its {!type:remote} (its public key), the last time a handshake
    operated with this {i initiator} and a function which is able to update
    to last timestamp when this {i initiator} tried a handshake. *)

val pkt_of_responder :
     now:(unit -> int)
  -> (responder, 'a) handshake
  -> msg2
  -> string
(** [pkt_of_responder ~now state uid msg2] returns a WireGuard packet which
    should be send to the {i initiator}. *)

val msg2_of_string :
     ?g:Mirage_crypto_rng.g
  -> Bakery.t
  -> Limiter.t
  -> now:(unit -> int)
  -> load:bool
  -> peer:Addr.t
  -> string
  -> ([ `Msg2 of msg2 | `Cookie of string ], [> `Msg of string ]) result
(** [msg2_of_string ?g bakery limiter ~now ~load ~peer pkt] tries to parse the
    given packet [pkt] from the given [peer] and extract a {!type:msg2} value. *)

type ('a, 'state) session

val step2 :
     now:(unit -> int)
  -> msg2
  -> t
  -> (initiator, pending) handshake
  -> ((initiator, confirmed) session, [> error ]) result

val session_of_responder :
     now:(unit -> int)
  -> (responder, confirmed) handshake
  -> ((responder, pending) session, [> error ]) result

val confirm : (responder, pending) session -> string -> ((responder, confirmed) session, [> error ]) result

type keys = { send : string; recv : string }

val keys : ('role, 'state) session -> keys

(**/*)

val tai64n : now:(unit -> int) -> string
(** See https://cr.yp.to/libtai/tai64.html.
    We have 10 years before the world ends. *)
