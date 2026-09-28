(* NOTE(dinosaure): see [drivers/net/wireguard/messages.h]. *)
let _REKEY_TIMEOUT = 5_000_000_000
let _KEEPALIVE_TIMEOUT = 10_000_000_000
let _REJECT_AFTER_TIME = 180_000_000_000
let _MAX_TIMER_HANDSHAKES = 90 / 5

type t =
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

let init ?persistent_keepalive_interval () =
  let persistent_keepalive_interval = match persistent_keepalive_interval with
    | Some interval when interval > 0 -> Some interval
    | _ -> None in
  { retransmit_handshake= None; send_keepalive= None; new_handshake= None
  ; zero_key_material= None; persistent_keepalive= None
  ; persistent_keepalive_interval
  ; handshake_attempts= 0
  ; need_another_keepalive= false
  ; sent_lastminute_handshake= false
  ; last_sent_handshake= None
  ; walltime_last_handshake= None }

let stop t =
  { t with retransmit_handshake= None; send_keepalive= None; new_handshake= None
         ; zero_key_material= None; persistent_keepalive= None }

let data_sent ~now ~jitter t =
  match t.new_handshake with
  | None -> { t with new_handshake= Some (now + _KEEPALIVE_TIMEOUT + _REKEY_TIMEOUT + jitter) }
  | Some _ -> t (* NOTE(dinosaure): already armed. *)

let data_received ~now t =
  match t.send_keepalive with
  | None -> { t with send_keepalive= Some (now + _KEEPALIVE_TIMEOUT) }
  | Some _ -> { t with need_another_keepalive= true }

let any_authenticated_packet_sent t = { t with send_keepalive= None }
let any_authenticated_packet_received t = { t with new_handshake= None }

let handshake_initiated ~now ~jitter t =
  { t with retransmit_handshake= Some (now + _REKEY_TIMEOUT + jitter) }

let handshake_complete ~timestamp t =
  { t with retransmit_handshake= None
         ; handshake_attempts= 0
         ; sent_lastminute_handshake= false
         ; walltime_last_handshake= Some timestamp }

let session_derived ~now t =
  { t with zero_key_material= Some (now + _REJECT_AFTER_TIME * 3) }

let any_authenticated_packet_traversal ~now t =
  match t.persistent_keepalive_interval with
  | Some interval -> { t with persistent_keepalive= Some (now + interval) }
  | None -> t

(* NOTE(dinosaure): handshake rate-limit *)
let can_send_handshake ~now t = match t.last_sent_handshake with
  | Some at -> now - at >= _REKEY_TIMEOUT
  | None -> true

let handshake_sent ~now t = { t with last_sent_handshake= Some now }
let reset_handshake_attempts t = { t with handshake_attempts= 0 }
let lastminute_handshake_sent t = { t with sent_lastminute_handshake= true }

type expiry =
  [ `Retransmit_handshake
  | `Give_up
  | `Send_keepalive
  | `New_handshake
  | `Zero_key_material
  | `Persistent_keepalive ]

let pp_expiry ppf = function
  | `Retransmit_handshake -> Fmt.string ppf "retransmit-handshake"
  | `Give_up -> Fmt.string ppf "give-up"
  | `Send_keepalive -> Fmt.string ppf "send-keepalive"
  | `New_handshake -> Fmt.string ppf "new-handshake"
  | `Zero_key_material -> Fmt.string ppf "zero-key-material"
  | `Persistent_keepalive -> Fmt.string ppf "persistent-keepalive"

let expired_retransmit_handshake ~now t =
  if t.handshake_attempts > _MAX_TIMER_HANDSHAKES then
    (* NOTE(dinosaure): we drop all packets without a keypair and don't try
       again, and we set a timer for destroying any residue that might be left
       of a partial exchange. *)
    let t = { t with send_keepalive= None } in
    let t = match t.zero_key_material with
      | None -> { t with zero_key_material= Some (now + _REJECT_AFTER_TIME * 3) }
      | Some _ -> t in
    Some `Give_up, t
  else
    Some `Retransmit_handshake, { t with handshake_attempts= t.handshake_attempts + 1 }

(* NOTE(dinosaure): on Linux, the keepalive is sent asynchronously (by a
   workqueue) {i after} this handler. So the re-armed timer is, in practice,
   deleted by [any_authenticated_packet_sent] when the keepalive is really sent.
   We keep the same order: re-arm here, the user sends the keepalive and calls
   [any_authenticated_packet_sent]. *)
let expired_send_keepalive ~now t =
  if t.need_another_keepalive
  then
    let t = { t with need_another_keepalive= false
                   ; send_keepalive= Some (now + _KEEPALIVE_TIMEOUT) } in
    Some `Send_keepalive, t
  else Some `Send_keepalive, t

let expired_new_handshake t = Some `New_handshake, t
let expired_zero_key_material t = Some `Zero_key_material, t

let expired_send_persistent_keepalive t =
  match t.persistent_keepalive_interval with
  | Some _ -> Some `Persistent_keepalive, t
  | None -> None, t

let due now = function Some at -> now >= at | None -> false

let expired ~now t =
  let step (r_expiries, t) (get, disarm, handler) =
    if due now (get t) then
      let expiry, t = handler (disarm t) in
      match expiry with
      | Some expiry -> (expiry :: r_expiries, t)
      | None -> (r_expiries, t)
    else (r_expiries, t) in
  let timers =
    [ (fun t -> t.retransmit_handshake), (fun t -> { t with retransmit_handshake= None })
    , expired_retransmit_handshake ~now
    ; (fun t -> t.send_keepalive), (fun t -> { t with send_keepalive= None })
    , expired_send_keepalive ~now
    ; (fun t -> t.new_handshake), (fun t -> { t with new_handshake= None })
    , expired_new_handshake
    ; (fun t -> t.zero_key_material), (fun t -> { t with zero_key_material= None })
    , expired_zero_key_material
    ; (fun t -> t.persistent_keepalive), (fun t -> { t with persistent_keepalive= None })
    , expired_send_persistent_keepalive ] in
  let r_expiries, t = List.fold_left step ([], t) timers in
  (List.rev r_expiries, t)

let deadline t =
  let fn acc = function
    | None -> acc
    | Some at -> match acc with
      | None -> Some at
      | Some best -> Some (Int.min best at) in
  List.fold_left fn None
    [ t.retransmit_handshake; t.send_keepalive; t.new_handshake
    ; t.zero_key_material; t.persistent_keepalive ]
