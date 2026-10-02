type error =
  [ `Invalid_IPv4_packet
  | `TTL_exceeded
  | `All_ports_used
  | `Msg of string ]

val pp_error : error Fmt.t

type t

val create : Ipaddr.V4.t -> t
val size : t -> int
val clean_up : t -> now:int -> unit

type ipv4_hdr =
  { ihl : int
  ; len : int
  ; uid : int
  ; df : bool
  ; mf : bool
  ; foff : int (* in bytes *)
  ; proto : int
  ; src : Ipaddr.V4.t
  ; dst : Ipaddr.V4.t }

val decode : string -> (ipv4_hdr, [> error ]) result
val inbound : t -> now:int -> ?hdr:ipv4_hdr -> bytes -> ((Ipaddr.V4.t * bytes) list, [> error ]) result
val outbound : t -> now:int -> ?mss:int -> ?hdr:ipv4_hdr -> bytes -> (int, [> error ]) result
val fragment : bytes -> mtu:int -> bytes list
