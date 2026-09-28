let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let guard ~err fn = if fn () then Ok () else Error err
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let cons_if_some v r = match v with None -> r | Some x -> x :: r
let ( let* ) = Result.bind

type error = Zostera.error

open Zostera

type current = Current : ('r, confirmed) session -> current

type previous =
  | Confirmed : ('r, confirmed) session -> previous
  | Unconfirmed : (responder, pending) session -> previous

module Q = struct
  type 'a t = { front : 'a list; back : 'a list; len : int }

  let empty = { front= []; back= []; len= 0 }
  let is_empty { len; _ } = len = 0
  let to_list t = t.front @ List.rev t.back

  let norm = function
    | { front= []; back; len } ->
      { front= List.rev back; back= []; len }
    | t -> t

  let pop = function
    | { front= []; _ } -> None
    | { front= x :: r; back; len } ->
      Some (x, norm { front= r; back; len= len - 1 })

  let push x t =
    let t, dropped =
      if t.len < 128 then t, None
      else match pop t with
      | Some (v, t) -> t, Some v | None -> t, None in
    norm { t with back= x :: t.back; len= t.len + 1 }, dropped
end

(* NOTE(dinosaure): [queue] is the [staged_packet_queue] of Linux. An empty
   string is a staged keepalive. *)
type peer =
  { remote : remote
  ; edn : Addr.t option
  ; timestamp : timestamp option
  ; last_initiation_consumption : int option
  ; prev : previous option
  ; curr : current option
  ; next : (responder, pending) session option
  ; handshake : (initiator, pending) Zostera.handshake option
  ; last_sent : int option
  ; last_recv : int option
  ; timers : Timers.t
  ; queue : string Q.t }

type t =
  { identity : Zostera.t
  ; bakery : Bakery.t
  ; limiter : Limiter.t
  ; peers : (string, peer) Hashtbl.t
  ; index : (Uid.t, string) Hashtbl.t
  ; mutable last_under_load : int option
  ; g : Mirage_crypto_rng.g option }

type action =
  [ `Send of Zostera.Addr.t * string
  | `Deliver of Zostera.public * string
  | `Drop of Zostera.public * string
  | `Error of error ]

type event =
  [ action
  | `Register of Uid.t
  | `Forget of Uid.t ]

let forget uid = `Forget uid

let create ?g identity =
  { identity; bakery= Bakery.create ?g ~me:identity (); limiter= Limiter.create ()
  ; peers= Hashtbl.create 0x7ff; index= Hashtbl.create 0x7ff
  ; last_under_load= None; g }

let _MAX_QUEUED_INCOMING_HANDSHAKES = 4096
let _INITIATIONS_PER_SECOND = 50

(* See [wg_receive_handshake_packet]. We are under load when [pending]
   handshake packets (not yet processed by the user) reach
   [MAX_QUEUED_INCOMING_HANDSHAKES / 8], and we stay under load for one second
   after the last time it happened. *)
let under_load t ~now ~pending =
  if pending >= _MAX_QUEUED_INCOMING_HANDSHAKES / 8 then begin
    t.last_under_load <- Some now;
    true end
  else match t.last_under_load with
    | None -> false
    | Some at ->
      let under_load = now - at < 1_000_000_000 in
      if not under_load then t.last_under_load <- None;
      under_load

let uid_of_session which peer =
  match which, peer.handshake, peer.prev, peer.curr, peer.next with
  | `Hshk, Some state, _, _, _ -> Some (Zostera.uid_of_initiator state)
  | `Prev, _, Some (Confirmed s), _, _ -> Some (Zostera.uid_of_local s)
  | `Prev, _, Some (Unconfirmed s), _, _ -> Some (Zostera.uid_of_local s)
  | `Curr, _, _, Some (Current s), _ -> Some (Zostera.uid_of_local s)
  | `Next, _, _, _, Some s -> Some (Zostera.uid_of_local s)
  | _ -> None

let uids peer =
  (* NOTE(dinosaure): a peer can have multiple unique IDs from its state,
     we collect all of them here. *)
  List.filter_map Fun.id
    [ uid_of_session `Hshk peer
    ; uid_of_session `Prev peer
    ; uid_of_session `Curr peer
    ; uid_of_session `Next peer ]

let rem t public =
  let key = Zostera.octets_of_public public in
  match Hashtbl.find_opt t.peers key with
  | None -> ()
  | Some peer ->
    let forget uid = match Hashtbl.find_opt t.index uid with
      | Some key' when Eqaf.equal key key' -> Hashtbl.remove t.index uid
      | _ -> () in
    List.iter forget (uids peer);
    Hashtbl.remove t.peers key

let apply t peer (events : event list) : action list =
  let key = Zostera.octets_of_remote peer.remote in
  Hashtbl.replace t.peers key peer;
  let fn = function
    | `Register uid -> Hashtbl.replace t.index uid key; None
    | `Forget uid -> Hashtbl.remove t.index uid; None
    | #action as action -> Some action in
  List.filter_map fn events

let fresh t =
  let rec go () =
    let uid = Uid.gen ?g:t.g () in
    if Hashtbl.mem t.index uid
    then go () else uid in
  go ()

(* See [timers.go]/[JitterMaxMs] and [REKEY_TIMEOUT_JITTER_MAX_JIFFIES]. *)
let jitter t =
  let buf = Mirage_crypto_rng.generate ?g:t.g 2 in
  (String.get_uint16_le buf 0 mod 334) * 1_000_000 (* [0, 333] ms *)

(* NOTE(dinosaure): about timers.

   Every timer-related field lives into [peer.timers] (see [Timers]) and hooks
   are called at the same places as Linux does into [send.c] and [receive.c].
   The name of the Linux function is given above each of our functions.

   On Linux, sending packets is asynchronous (workqueues): the timer hooks of
   an emission ([any_authenticated_packet_sent], [data_sent]) are executed
   {i after} the hooks of the reception which triggered it. We are synchronous,
   so we reproduce this order by applying reception hooks first and emitting
   packets then. *)

(* Out *)

(* [wg_packet_send_handshake_initiation] *)
let send_handshake_initiation t ~timestamp ~now peer edn r_events =
  if not (Timers.can_send_handshake ~now peer.timers) then (peer, r_events)
  else
    let uid = fresh t in
    match Zostera.step0 ?g:t.g ~uid ~timestamp t.identity peer.remote with
    | Error err -> (peer, `Error err :: r_events)
    | Ok (state, msg1) ->
      let pkt = Zostera.msg1_to_string ~now state msg1 in
      (* NOTE(dinosaure): a new initiation replaces the previous one. *)
      let r_events = cons_if_some (Option.map forget (uid_of_session `Hshk peer)) r_events in
      let timers =
        peer.timers
        |> Timers.any_authenticated_packet_traversal ~now
        |> Timers.any_authenticated_packet_sent
        |> Timers.handshake_sent ~now
        |> Timers.handshake_initiated ~now ~jitter:(jitter t) in
      let peer = { peer with handshake= Some state; last_sent= Some now; timers } in
      (peer, `Send (edn, pkt) :: `Register uid :: r_events)

(* [wg_packet_send_queued_handshake_initiation]

   § 6.4:
   > If a handshake response message is not subsequently received after
   > [REKEY_TIMEOUT] seconds, a new handshake initiation message is
   > constructed and sent.

   [is_retry] is [true] only when the [retransmit_handshake] timer expires. *)
let send_queued_handshake_initiation t ~timestamp ~now ~is_retry peer r_events =
  let peer =
    if is_retry then peer
    else { peer with timers= Timers.reset_handshake_attempts peer.timers } in
  if not (Timers.can_send_handshake ~now peer.timers) then (peer, r_events)
  else match peer.edn with
    | None -> (peer, `Error (msgf "Unknown endpoint") :: r_events)
    | Some edn -> send_handshake_initiation t ~timestamp ~now peer edn r_events

(* [keep_key_fresh] from [send.c], see § 6.2. *)
let keep_key_fresh_on_send t ~timestamp ~now peer r_events =
  match peer.curr with
  | Some (Current curr)
    when not (Zostera.expired ~now curr) && Zostera.rekey_on_send ~now curr ->
    send_queued_handshake_initiation t ~timestamp ~now ~is_retry:false peer r_events
  | Some _ | None -> (peer, r_events)

(* [wg_packet_create_data_done] *)
let create_data_done t ~timestamp ~now ~data_sent peer r_events =
  let timers =
    peer.timers
    |> Timers.any_authenticated_packet_traversal ~now
    |> Timers.any_authenticated_packet_sent in
  let timers =
    if data_sent then Timers.data_sent ~now ~jitter:(jitter t) timers
    else timers in
  let peer = { peer with timers; last_sent= Some now } in
  keep_key_fresh_on_send t ~timestamp ~now peer r_events

(* [wg_packet_send_staged_packets]

   We encrypt all staged packets with the current session. If we are not able
   to do so (no session, expired or exhausted session), packets stay into the
   queue and we initiate a new handshake. § 6.4:

   > The first time the user sends a packet over a WireGuard interface, the
   > packet cannot immediately be sent, because no current session exists. So,
   > after queuing the packet, WireGuard sends a handshake initiation message.
*)
let send_staged_packets t ~timestamp ~now peer r_events =
  if Q.is_empty peer.queue then (peer, r_events)
  else
    match peer.curr, peer.edn with
    | Some (Current session), Some edn when not (Zostera.expired ~now session) ->
      let fn acc data =
        let* r_pkts = acc in
        let* pkt = Zostera.send ~now session data in
        Ok ((pkt, not (String.is_empty data)) :: r_pkts) in
      begin match List.fold_left fn (Ok []) (Q.to_list peer.queue) with
      | Ok r_pkts ->
        let data_sent = List.exists snd r_pkts in
        let fn r_events (pkt, _) = `Send (edn, pkt) :: r_events in
        let r_events = List.fold_left fn r_events (List.rev r_pkts) in
        let peer = { peer with queue= Q.empty } in
        create_data_done t ~timestamp ~now ~data_sent peer r_events
      | Error _ ->
        send_queued_handshake_initiation t ~timestamp ~now ~is_retry:false peer r_events
      end
    | _ ->
      send_queued_handshake_initiation t ~timestamp ~now ~is_retry:false peer r_events

(* [wg_packet_send_keepalive] *)
let send_keepalive t ~timestamp ~now peer r_events =
  let peer =
    if Q.is_empty peer.queue
    then { peer with queue= fst (Q.push String.empty peer.queue) }
    else peer in
  send_staged_packets t ~timestamp ~now peer r_events

let add ?psk ?edn ?persistent_keepalive t ~timestamp ~now public =
  let key = Zostera.octets_of_public public in
  let me = Zostera.octets_of_public (Zostera.public t.identity) in
  (* NOTE(dinosaure): see [netlink.c]/[set_peer], we silently ignore peers
     that have the same public key as us. Otherwise, someone can reflect our
     own [msg1] to us. It's silent so that the same list of peers can be used
     everywhere. *)
  if Eqaf.equal key me then Ok [] else
  let* remote = Zostera.remote ?psk t.identity public in
  let* () = guard ~err:(msgf "The given peer already exists") @@ fun () ->
    Hashtbl.mem t.peers key = false in
  let persistent_keepalive_interval =
    Option.map (fun secs -> secs * 1_000_000_000) persistent_keepalive in
  let timers = Timers.init ?persistent_keepalive_interval () in
  let peer =
    { remote; edn; timestamp= None; last_initiation_consumption= None
    ; prev= None; curr= None; next= None; handshake= None
    ; last_sent= None; last_recv= None
    ; timers; queue= Q.empty } in
  Hashtbl.replace t.peers key peer;
  (* NOTE(dinosaure): see [netlink.c]/[set_peer], when a persistent keepalive
     is set, we directly send a keepalive (which initiates a handshake). *)
  match timers.Timers.persistent_keepalive_interval, edn with
  | Some _, Some _ ->
    let peer, r_events = send_keepalive t ~timestamp ~now peer [] in
    Ok (apply t peer (List.rev r_events))
  | _ -> Ok []

(* In *)

(* [keep_key_fresh] from [receive.c], see § 6.2. The time-based opportunistic
   rekeying is restricted to the initiator and done only once per session. *)
let keep_key_fresh_on_recv t ~timestamp ~now peer r_events =
  if peer.timers.Timers.sent_lastminute_handshake then (peer, r_events)
  else match peer.curr with
    | Some (Current curr) when not (Zostera.expired ~now curr) ->
      begin match Zostera.role curr with
      | Zostera.Initiator when Zostera.rekey_on_recv ~now curr ->
        let peer = { peer with timers= Timers.lastminute_handshake_sent peer.timers } in
        send_queued_handshake_initiation t ~timestamp ~now ~is_retry:false peer r_events
      | Zostera.Initiator | Zostera.Responder -> (peer, r_events) end
    | Some _ | None -> (peer, r_events)

(* [MESSAGE_HANDSHAKE_INITIATION] from [wg_receive_handshake_packet] and
   [wg_packet_send_handshake_response]. *)
let on_msg1 t ~now ~load ~from pkt =
  let* out = Zostera.msg1_of_string ?g:t.g t.bakery t.limiter ~now ~load ~peer:from pkt in
  match out with
  | `Cookie pkt -> Ok [ `Send (from, pkt) ]
  | `Msg1 msg1 ->
    let found = ref None in
    let fn public =
      let key = Zostera.octets_of_public public in
      match Hashtbl.find_opt t.peers key with
      | None -> `Reject
      | Some peer ->
        let set ts = found := Some (peer, ts) in
        `Accept (peer.remote, peer.timestamp, set) in
    let uid = fresh t in
    let* handshake, msg2 = Zostera.step1 ?g:t.g ~uid ~peer:fn msg1 t.identity in
    let* peer, ts = Option.to_result ~none:(msgf "Unaccepted initiator") !found in
    (* NOTE(dinosaure): see [wg_noise_handshake_consume_initiation], we accept
       at most [INITIATIONS_PER_SECOND] [msg1] per peer. As the replay
       protection (see [Zostera.step1]), it's done after the decryption of the
       timestamp, so only an authenticated initiator can trigger it. *)
    let* () = guard ~err:(msgf "Handshake initiation flood") @@ fun () ->
      match peer.last_initiation_consumption with
      | Some at -> now - at >= 1_000_000_000 / _INITIATIONS_PER_SECOND
      | None -> true in
    let* session = session_of_responder ~now handshake in
    let pkt = Zostera.msg2_to_string ~now handshake msg2 in
    let timers =
      peer.timers
      (* [wg_packet_send_handshake_response] *)
      |> Timers.session_derived ~now
      |> Timers.any_authenticated_packet_traversal ~now
      |> Timers.any_authenticated_packet_sent
      |> Timers.handshake_sent ~now
      (* end of [wg_receive_handshake_packet] *)
      |> Timers.any_authenticated_packet_received
      |> Timers.any_authenticated_packet_traversal ~now in
    (* NOTE(dinosaure): we forget [prev] and [next] sessions. *)
    let forget = [] in
    let forget = cons_if_some (uid_of_session `Prev peer) forget in
    let forget = cons_if_some (uid_of_session `Next peer) forget in
    let forget = List.map (fun uid -> `Forget uid) forget in
    (* NOTE(dinosaure): and replace [next] by [Some session] (from
       [session_of_responder]).

       § 6.3:
       > Every time a new secure session is created, for the responder, the
       > [next] slot is used _interstitially_ until the handshake is confirmed.

       NOTE(dinosaure): [edn= Some from], see [wg_receive_handshake_packet] and
       [wg_socket_set_peer_endpoint_from_skb] in the
       [MESSAGE_HANDSHAKE_INITIATION] case. *)
    let peer =
      { peer with timestamp= Some ts; edn= Some from
                ; last_initiation_consumption= Some now
                ; last_recv= Some now; last_sent= Some now
                ; prev= None; next= Some session; timers } in
    (* NOTE(dinosaure): do [forget] first, [`Register] then and [`Send]. *)
    let r_events = (`Send (from, pkt) :: `Register uid :: forget) in
    Ok (apply t peer (List.rev r_events))

(* [MESSAGE_HANDSHAKE_RESPONSE] from [wg_receive_handshake_packet]. *)
let on_msg2 t ~timestamp ~now ~load ~from uid peer pkt =
  let* out = Zostera.msg2_of_string ?g:t.g t.bakery t.limiter ~now ~load ~peer:from pkt in
  match out, peer.handshake with
  | `Cookie pkt, _ -> Ok (peer, [ `Send (from, pkt) ])
  | `Msg2 _, None -> error_msgf "Unexpected handshake response"
  | `Msg2 msg2, Some state ->
    (* NOTE(dinosaure): due to [Some state], we prove that we are the initiator.
       Only the initiator can have such value. *)
    let* () = guard ~err:(msgf "Unexpected receiver") @@ fun () ->
      Zostera.uid_of_initiator state = uid in
    let* session = Zostera.step2 ~now msg2 t.identity state in
    let forget = [] in
    let forget = match peer.next with
      | Some _ ->
        forget
        |> cons_if_some (uid_of_session `Prev peer)
        |> cons_if_some (uid_of_session `Curr peer)
      | None ->
        cons_if_some (uid_of_session `Prev peer) forget in
    let forget = List.map (fun uid -> `Forget uid) forget in
    let prev = match peer.next, peer.curr with
      | Some next, _ -> Some (Unconfirmed next)
        (* NOTE(dinosaure): see wireguard-linux, [add_newkeypairs]:

           If there already was a next keypair pending, we demote it to be the
           previous keypair, and free the existing current. Note that this means
           KCI can result in this transition. It would perhaps be more sound to
           always just get rid of the unused next keypair instead of putting it
           in the previous slot, but this might be a bit less robust. Something
           to think about for the future. *)
      | None, Some (Current curr) -> Some (Confirmed curr)
      | None, None -> None in
    let timers =
      peer.timers
      |> Timers.session_derived ~now
      |> Timers.handshake_complete ~timestamp
      |> Timers.any_authenticated_packet_received
      |> Timers.any_authenticated_packet_traversal ~now in
    (* NOTE(dinosaure): for [edn= Some from], see [wg_receive_handshake_packet]
       and [wg_socket_set_peer_endpoint_from_skb] in the
       [MESSAGE_HANDSHAKE_RESPONSE] case. *)
    let peer =
      { peer with edn= Some from; last_recv= Some now
                ; prev; curr= Some (Current session); next= None
                ; handshake= None; timers } in
    (* NOTE(dinosaure): it sends staged packets or, if there are none, a
       keepalive to give an immediate confirmation of the session. *)
    Ok (send_keepalive t ~timestamp ~now peer forget)

(* [MESSAGE_HANDSHAKE_COOKIE], no timers are involved. *)
let on_cookie ~now uid peer pkt =
  let* () = guard ~err:(msgf "Unexpected cookie") @@ fun () ->
    uid_of_session `Hshk peer = Some uid
    || uid_of_session `Next peer = Some uid in
   let* () = Zostera.consume_cookie peer.remote ~now ~uid pkt in
   Ok (peer, [])

(* NOTE(dinosaure): here, we rotate sessions:
   - the [t.curr] session becomes [t.prev]
   - the given session is new new [t.curr] session
   - [t.next] becomes [None] in any cases *)
let rotate peer session =
  let forget = cons_if_some (uid_of_session `Prev peer) [] in
  let forget = List.map (fun uid -> `Forget uid) forget in
  let prev = match peer.curr with
    | Some (Current curr) -> Some (Confirmed curr)
    | None -> None in
  ({ peer with prev; curr= Some (Current session); next= None }, forget)

(* [wg_packet_consume_data_done] *)
let on_data t ~timestamp ~now ~from uid peer pkt =
  let* peer, out, confirmed, r_events = match peer with
    | { next= Some next; _ } when Zostera.uid_of_local next = uid ->
      let* session, out = Zostera.confirm ~now next pkt in
      let peer, r_events = rotate peer session in
      Ok (peer, out, true, r_events)
    | { curr= Some (Current curr); _ } when Zostera.uid_of_local curr = uid ->
      let* out = Zostera.recv ~now curr pkt in
      Ok (peer, out, false, [])
    | { prev= Some (Confirmed prev); _ } when Zostera.uid_of_local prev = uid ->
      let* out = Zostera.recv ~now prev pkt in
      Ok (peer, out, false, [])
    | { prev= Some (Unconfirmed prev); _ } when Zostera.uid_of_local prev = uid ->
      let* session, out = Zostera.confirm ~now prev pkt in
      Ok ({ peer with prev= Some (Confirmed session) }, out, false, [])
    | _ -> error_msgf "Unexpected receiver" in
  (* NOTE(dinosaure): only now, after decryption and validation of the
     counter, we can update the endpoint. *)
  let timers = peer.timers in
  let timers =
    if confirmed then Timers.handshake_complete ~timestamp timers
    else timers in
  let timers =
    timers
    |> Timers.any_authenticated_packet_received
    |> Timers.any_authenticated_packet_traversal ~now in
  let timers, r_events = match out with
    | `Keepalive -> (timers, r_events)
    | `Data data ->
      let public = Zostera.public_of_remote peer.remote in
      (Timers.data_received ~now timers, `Deliver (public, data) :: r_events) in
  let peer = { peer with edn= Some from; last_recv= Some now; timers } in
  let peer, r_events =
    if confirmed then send_staged_packets t ~timestamp ~now peer r_events
    else (peer, r_events) in
  Ok (keep_key_fresh_on_recv t ~timestamp ~now peer r_events)

let packet t ~timestamp ~now ?(pending = 0) ~from pkt =
  let* k =
    let* () = guard ~err:(msgf "Truncated WireGuard packet") @@ fun () ->
      String.length pkt >= 4 in
    Ok (String.get_int32_le pkt 0) in
  (* NOTE(dinosaure): as Linux, the load is only computed for [msg1] and
     [msg2] (cookies are consumed before). *)
  let load () = under_load t ~now ~pending in
  match k with
  | 1l -> on_msg1 t ~now ~load:(load ()) ~from pkt
  | 2l | 3l | 4l ->
    let* uid = Uid.receiver pkt in
    let* key = Option.to_result ~none:(msgf "Unknown receiver") (Hashtbl.find_opt t.index uid) in
    let* peer = Option.to_result ~none:(msgf "Orphan unique ID") (Hashtbl.find_opt t.peers key) in
    let* peer, r_events = match k with
      | 2l -> on_msg2 t ~timestamp ~now ~load:(load ()) ~from uid peer pkt
      | 3l -> on_cookie ~now uid peer pkt
      | _ -> on_data t ~timestamp ~now ~from uid peer pkt in
    Ok (apply t peer (List.rev r_events))
  | _ -> error_msgf "Unknown packet type"

(* [wg_xmit] *)
let write t ~timestamp ~now public = function
  | "" -> Ok []
  | data ->
    let key = Zostera.octets_of_public public in
    (* NOTE(dinosaure): a packet **must** have an endpoint. *)
    let* peer = Option.to_result ~none:(msgf "Unknown peer") (Hashtbl.find_opt t.peers key) in
    (* NOTE(dinosaure): see [send_staged_packets], we send packets only if a
       current session is available. In the case of the responder, such session
       can exist only if we [Zostera.confirm]. If it's not the case, we just
       fill our queue until the initiator send to use a keep-alive or a data
       packet to confirm our session. *)
    let queue, dropped = Q.push data peer.queue in
    let r_events = match dropped with
      | Some x when not (String.is_empty x) ->
        [ `Drop (Zostera.public_of_remote peer.remote, x) ]
      | Some _ | None -> [] in
    let peer, r_events = send_staged_packets t ~timestamp ~now { peer with queue } r_events in
    Ok (apply t peer (List.rev r_events))

(* Tick *)

(* [wg_packet_purge_staged_packets] *)
let purge_staged_packets peer r_events =
  let public = Zostera.public_of_remote peer.remote in
  let fn r_events = function
    | "" -> r_events
    | data -> `Drop (public, data) :: r_events in
  let r_events = List.fold_left fn r_events (Q.to_list peer.queue) in
  ({ peer with queue= Q.empty }, r_events)

(* [wg_queued_expired_zero_key_material], § 6.3:

   > If no new secure session is created after [REJECT_AFTER_TIME × 3]
   > seconds, the current secure session, the previous secure session, and
   > potentially the next secure session are discarded and zeroed out, in
   > addition to any possible partially-completed handshake states and
   > ephemeral keys. *)
let zero_key_material peer r_events =
  let r_events = List.rev_append (List.map forget (uids peer)) r_events in
  ({ peer with prev= None; curr= None; next= None; handshake= None }, r_events)

let tick t ~timestamp ~now peer =
  let expiries, timers = Timers.expired ~now peer.timers in
  let fn (peer, r_events) = function
    | `Retransmit_handshake ->
      send_queued_handshake_initiation t ~timestamp ~now ~is_retry:true peer r_events
    | `Give_up -> purge_staged_packets peer r_events
    | `Send_keepalive | `Persistent_keepalive ->
      send_keepalive t ~timestamp ~now peer r_events
    | `New_handshake ->
      send_queued_handshake_initiation t ~timestamp ~now ~is_retry:false peer r_events
    | `Zero_key_material -> zero_key_material peer r_events in
  List.fold_left fn ({ peer with timers }, []) expiries

let tick t ~timestamp ~now =
  let peers = Hashtbl.fold (fun _ peer acc -> peer :: acc) t.peers [] in
  let fn peer =
    let peer, r_events = tick t ~timestamp ~now peer in
    apply t peer (List.rev r_events) in
  List.concat_map fn peers

let deadline t =
  let fn _ peer acc = match acc, Timers.deadline peer.timers with
    | None, at | at, None -> at
    | Some a, Some b -> Some (Int.min a b) in
  Hashtbl.fold fn t.peers None
