type t
type error = Zostera.error

val create : ?g:Mirage_crypto_rng.g -> Zostera.t -> t

type action =
  [ `Send of Zostera.Addr.t * string
  | `Deliver of Zostera.public * string
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
  -> from:Zostera.Addr.t
  -> string
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
