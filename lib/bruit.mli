type t
type error = Zostera.error

val create : ?g:Mirage_crypto_rng.g -> Zostera.t -> t
val add : ?psk:Zostera.psk -> ?edn:Zostera.Addr.t -> t -> Zostera.public -> (unit, [> error ]) result
val rem : t -> Zostera.public -> unit

type action =
  [ `Send of Zostera.Addr.t * string 
  | `Deliver of Zostera.public * string
  | `Drop of Zostera.public * string
  | `Error of error ]

val packet : t -> timestamp:int -> now:int -> load:bool -> from:Zostera.Addr.t -> string -> (action list, [> error ]) result
val write : t -> timestamp:int -> now:int -> Zostera.public -> string -> (action list, [> error ]) result
val tick : t -> timestamp:int -> now:int -> action list
val deadline : t -> int option
