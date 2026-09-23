(** {2 Unique ID.}

    A 32-bit index that locally represents the other peer, analogous to IPsec's
    "SPI". *)

type t = private int32
(** Type of unique IDs. *)

val gen : ?g:Mirage_crypto_rng.g -> unit -> t
(** [gen ?g ()] generates a new unique ID. *)

val receiver : string -> (t, [> `Msg of string ]) result
(** [receiver pkt] extracts the unique ID from the given packet [pkt]. It does
    not validate the given packet as a well-formed WireGuard packet, it just
    extracts its receiver ID. *)

(**/*)

val unsafe_of_int32 : int32 -> t
