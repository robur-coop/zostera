(** Zostera, a pure implementation of the Wireguard protocol.

    This module implements the Wireguard protocol which is described here:
    https://www.wireguard.com/papers/wireguard.pdf

    {[
      initiator     receiver
          |            |
          | -- msg1 -> |
          |            |
          | <- msg2 -- |
    ]}
*)

type error = [ `Msg of string | `Invalid_cookie | Mirage_crypto_ec.error ]
(** Error returned by the handshake steps and the packet decoders. The only
    thing to do in the event of an error is to {i drop} the current operation
    (drop packets and cancel handshakes). *)

val pp_error : error Fmt.t
(** Pretty printer for {!type:error} values. *)

module Uid = Uid

(** {2 Pre-shared Symmetric Key.}

    The secrecy of all data sent via WireGuard relies on the security of the
    Curve25529 ECDH function. In order to mitigate any future advances in
    quantum computing, WireGuard also support a mode in which any pair of peers
    might additionally pre-share a single 256-bit (32 bytes) symmetric
    encryption key between themselves, in order to add an additional layer of
    symmetric encryption. *)

type psk
(** Type of pre-shared symmetric keys. *)

val psk : string -> psk
(** [psk octets] is a pre-shared symmetric key.

    @raise Invalid_argument if [octets] is not a 32-bytes string. *)

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
  -> uid:Uid.t
  -> string
  -> (unit, [> error ]) result
(** [consume_cookie remote ~now ~uid pkt] validates the received cookie from
    the given [remote] (with its [uid] according to the current handshake, see
    {!val:uid_of_initiator}). *)

(** {2 Bakery of cookies.}

    A WireGuard node may be under load when processing several handshakes at
    the same time. In this case, the node may respond to certain peers with a
    cookie that delays the handshake. Peers then use this cookie in order to
    resent the message and have it be accepted the following time by the node.

    The node maintains a secret random value that changes every two minutes. A
    cookie is simply the result of computing a {i mac} of the peer's source IP
    address using this changing secret as the {i mac} key. The peer, when
    resending its message, sends a {i mac} of its message using this cookie as
    the {i mac} key. Then the node receives the message, if it is under load,
    it may choose whether or not to accept and process the message based on
    whether or not there is a correct {i mac} that uses the cookie as a key.

    A {i bakery} is a global variable at the node level used to generate these
    cookies based on a secret {i Rm}, which is updated lazily every 2 minutes.
*)

module Bakery : sig
  type identity = t
  (** The type of identities. *)

  type t (** The type of bakeries. *)

  val create : ?g:Mirage_crypto_rng.g -> me:identity -> unit -> t
  (** [create ?g ~me ()] creates a new bakery which is able to generate cookies
      if needed during handshakes. *)
end

module Addr = Addr
module Limiter = Limiter
module Window = Window

(** {2 Timestamps.}

    Having authentication in the first packet like this potentially opens up
    the responder to a replay attack. An attacker could replay initial
    handshake messages to trick the responder into regenerating its ephemeral
    key, thereby invalidating the session of the legitimate initiator (though
    not affecting the secrecy or authenticity of any messages). To prevent
    this, a timestamp is included, encrypted and authenticated, in the first
    message ({!type:msg1}). The responder keeps track of the greatest timestamp
    received per peer (that is the reason for {!val:newer}) and discards
    packets containing timestamps less than or equal to it. This timestamp
    ensures that an attacker may not disrupt a current session between
    initiator and responder via replay attack.

    In this case, the {!val:step1} function processes the first message and
    asks the user for authorisation from a potential initiator. The user must
    respond, based on the public key provided by {!type:msg1}, either by
    rejecting ([`Reject`]) or accepting with:
    1) the latest date on which this initiator attempted the handshake
    2) a function enabling this date to be updated on the user's side
*)

type timestamp
(** Type of timestamps (TAI64N). *)

val newer : timestamp -> timestamp -> bool
(** [newer t0 t1] returns [true] if [t0 < t1]. Otherwise, it returns [false]. *)

type initiator = private [ `initiator ]
type responder = private [ `responder ]

type pending
type confirmed

type ('role, 'state) handshake

type 'role role =
  | Initiator : initiator role
  | Responder : responder role

val uid_of_initiator : (initiator, pending) handshake -> Uid.t

type msg1
(** Type of the first message that an {i initiator} should send to the
    {i responder}. *)

val step0 :
     ?g:Mirage_crypto_rng.g
  -> ?uid:Uid.t
  -> now:(unit -> int)
  -> t
  -> remote
  -> ((initiator, pending) handshake * msg1, [> error ]) result
(** [step0 ?g ~now identity remote] generates a new handshake state and a
    {!type:msg1} that's the user can send to the {i responder}. *)

val msg1_to_string :
     now:(unit -> int)
  -> (initiator, pending) handshake
  -> msg1
  -> string
(** [msg1_to_string ~now state msg1] returns a WireGuard packet which should
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
  -> ?uid:Uid.t
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

val msg2_to_string :
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

val role : ('role, 'state) session -> 'role role
val uid_of_local : ('role, 'state) session -> Uid.t
val uid_of_peer : ('role, 'state) session -> Uid.t

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

type out =
  [ `Keepalive
  | `Data of string ]

val confirm :
     now:(unit -> int)
  -> (responder, pending) session
  -> string
  -> ((responder, confirmed) session * out, [> error ]) result

val recv :
     now:(unit -> int)
  -> ('role, confirmed) session
  -> string
  -> (out, [> error ]) result

val send :
     now:(unit -> int)
  -> ('role, confirmed) session
  -> string
  -> (string, [> error ]) result

val keepalive :
     now:(unit -> int)
  -> ('role, confirmed) session
  -> (string, [> error ]) result

val expired : now:(unit -> int) -> ('role, 'state) session -> bool
val rekey_on_send : now:(unit -> int) -> ('role, 'state) session -> bool
val rekey_on_recv : now:(unit -> int) -> (initiator, 'state) session -> bool

type keys = { send : string; recv : string }

val keys : ('role, 'state) session -> keys

(**/*)

val tai64n : now:(unit -> int) -> string
(** See https://cr.yp.to/libtai/tai64.html.
    We have 10 years before the world ends. *)
