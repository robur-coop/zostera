(** Bruit is the implementation of WireGuard's state machine. Starting with an
    identity, you can add or remove peers and communicate with them via
    accurate sessions. This state machine updates the internal sessions for
    peers according to their expiry times. *)

type t
type error = Zostera.error

val create : ?g:Mirage_crypto_rng.g -> Zostera.t -> t

module Ecn : sig
  val _HANDSHAKE_DSCP : int

  val dsfield : string -> int
  val encap : string -> int
  val decap : outer:int -> string -> string
  val decap_into : outer:int -> bytes -> len:int -> unit
end

type action =
  [ `Send of Zostera.Addr.t * int * string
  | `Deliver of Zostera.public * bytes * int
  | `Drop of Zostera.public * string
  | `Error of error ]

val add :
     ?psk:Zostera.psk
  -> ?edn:Zostera.Addr.t
  -> ?persistent_keepalive:int
  -> t
  -> timestamp:int
  -> now:int
  -> Zostera.public
  -> (action list, [> error ]) result

val rem : t -> Zostera.public -> unit

val packet :
     t
  -> timestamp:int
  -> now:int
  -> ?pending:int
  -> ?ds:int
  -> from:Zostera.Addr.t
  -> string
  -> (action list * string option, [> error ]) result

val packet_into :
     t
  -> timestamp:int
  -> now:int
  -> ?pending:int
  -> ?ds:int
  -> from:Zostera.Addr.t
  -> string
  -> bytes
  -> (action list, [> error ]) result

val write :
     t
  -> timestamp:int
  -> now:int
  -> Zostera.public
  -> string
  -> (action list, [> error ]) result

val tick :
     t
  -> timestamp:int
  -> now:int
  -> action list

val deadline : t -> int option
