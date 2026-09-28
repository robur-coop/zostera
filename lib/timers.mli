val _REKEY_TIMEOUT : int
val _KEEPALIVE_TIMEOUT : int
val _REJECT_AFTER_TIME : int
val _MAX_TIMER_HANDSHAKES : int

type t = private
  { retransmit_handshake : int option
  ; send_keepalive : int option
  ; new_handshake : int option
  ; zero_key_material : int option
  ; persistent_keepalive : int option
  ; persistent_keepalive_interval : int option
  ; handshake_attempts : int
  ; need_another_keepalive : bool
  ; sent_lastminute_handshake : bool
  ; last_sent_handshake : int option
  ; walltime_last_handshake : int option }

val init : ?persistent_keepalive_interval:int -> unit -> t
val stop : t -> t

val data_sent : now:int -> jitter:int -> t -> t
val data_received : now:int -> t -> t
val any_authenticated_packet_sent : t -> t
val any_authenticated_packet_received : t -> t
val handshake_initiated : now:int -> jitter:int -> t -> t
val handshake_complete : timestamp:int -> t -> t
val session_derived : now:int -> t -> t
val any_authenticated_packet_traversal : now:int -> t -> t
val can_send_handshake : now:int -> t -> bool
val handshake_sent : now:int -> t -> t
val reset_handshake_attempts : t -> t
val lastminute_handshake_sent : t -> t

type expiry =
  [ `Retransmit_handshake
  | `Give_up
  | `Send_keepalive
  | `New_handshake
  | `Zero_key_material
  | `Persistent_keepalive ]

val pp_expiry : expiry Fmt.t

val expired : now:int -> t -> expiry list * t
val deadline : t -> int option
