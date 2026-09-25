[@@@warning "-27-32-34-37"]

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

type handshake =
  { state : (initiator, pending) Zostera.handshake
  ; first : int (* first try *)
  ; retry_at : int (* sent + REKEY_TIMEOUT + jitter *) }

module Q = struct
  type 'a t = { front : 'a list; back : 'a list; len : int }

  let empty = { front= []; back= []; len= 0 }
  let is_empty { len; _ } = len = 0
  let to_list t = t.front @ List.rev t.back
  let unsafe_of_list lst = { front= lst; back= []; len= List.length lst }

  let norm = function
    | { front= []; back; len } ->
      { front= List.rev back; back= []; len }
    | t -> t

  let peek = function
    | { front= []; _ } -> None
    | { front= x :: _; _ } -> Some x

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

type peer =
  { remote : remote
  ; edn : Addr.t option
  ; timestamp : timestamp option
  ; prev : previous option
  ; curr : current option
  ; next : (responder, pending) session option
  ; handshake : handshake option
  ; last_handshake : int option
  ; last_handshake_sent : int option
  ; last_sent : int option
  ; last_recv : int option
  ; keepalive_at : int option
  ; new_handshake_at : int option
  ; zero_keys_at : int option 
  ; queue : string Q.t }

type t =
  { identity : Zostera.t
  ; bakery : Bakery.t
  ; limiter : Limiter.t
  ; peers : (string, peer) Hashtbl.t
  ; index : (Uid.t, string) Hashtbl.t
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

let _KEEPALIVE_TIMEOUT = 10_000_000_000
let _REKEY_AFTER_TIME = 120_000_000_000
let _REKEY_ATTEMPT_TIME = 90_000_000_000
let _REKEY_TIMEOUT = 5_000_000_000
let _REJECT_AFTER_TIME = 180_000_000_000

let create ?g identity =
  { identity; bakery= Bakery.create ?g ~me:identity (); limiter= Limiter.create ()
  ; peers= Hashtbl.create 0x7ff; index= Hashtbl.create 0x7ff; g }

let add ?psk ?edn t public =
  let* remote = Zostera.remote ?psk t.identity public in
  let timestamp = None
  and prev = None and curr = None and next = None and handshake = None
  and last_handshake = None and last_handshake_sent = None
  and last_sent = None and last_recv = None
  and keepalive_at = None and new_handshake_at = None and zero_keys_at = None
  and queue = Q.empty in
  let peer =
    { remote; edn; timestamp; prev; curr; next; handshake
    ; last_handshake; last_handshake_sent
    ; last_sent; last_recv
    ; keepalive_at; new_handshake_at; zero_keys_at
    ; queue } in
  let key = Zostera.octets_of_public public in
  let* () = guard ~err:(msgf "The given peer already exists") @@ fun () ->
    Hashtbl.mem t.peers key = false in
  Hashtbl.replace t.peers key peer;
  Ok ()

let uid_of_session which peer =
  match which, peer.handshake, peer.prev, peer.curr, peer.next with
  | `Hshk, Some { state; _ }, _, _, _ -> Some (Zostera.uid_of_initiator state)
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

(* NOTE(dinosaure): about rotation

when the handshake is done:
initiator
  if next != null
    next <- null
    curr <- new
    prev <- next
  else
    prev <- curr
    curr <- new

responder
  next <- new
  prev <- null

when we receive date packet:
delete(old)
prev <- curr
curr <- new (and new == next)
next <- null

*)

(* In *)

let on_msg1 t ~now ~load ~from pkt =
  let* out = Zostera.msg1_of_string ?g:t.g t.bakery t.limiter ~now ~load ~peer:from pkt in
  match out with
  | `Cookie pkt -> Ok [ `Send (from, pkt) ]
  | `Msg1 msg1 ->
    (* TODO(dinosaure): [HandshakeInitiationRate], protect us against a peer which sends too many [msg1]. *)
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
    let* session = session_of_responder ~now handshake in
    let peer = { peer with new_handshake_at= None } in
    let pkt = Zostera.msg2_to_string ~now handshake msg2 in
    let peer = { peer with timestamp= Some ts; edn= Some from
                         ; last_recv= Some now; last_sent= Some now; last_handshake_sent= Some now
                         ; keepalive_at= None
                         ; zero_keys_at= Some (now + 3 * _REJECT_AFTER_TIME) } in
    (* NOTE(dinosaure): we forget [prev] and [next] sessions. *)
    let forget = [] in
    let forget = cons_if_some (uid_of_session `Prev peer) forget in
    let forget = cons_if_some (uid_of_session `Next peer) forget in
    let forget = List.map (fun uid -> `Forget uid) forget in
    (* NOTE(dinosaure): and replace [next] by [Some session] (from
       [session_of_responder]).

       § 6.3:
       > Every time a new secure session is created, for the responder, the
       > [next] slot is used _interstitially_ until the handshake is confirmed. *)
    let peer = { peer with prev= None; next= Some session; last_handshake= Some now } in
    (* NOTE(dinosaure): do [forget] first, [`Register] then and [`Send]. *)
    let r_events = (`Send (from, pkt) :: `Register uid :: forget) in
    Ok (apply t peer (List.rev r_events))

let send ~now peer (Current session) data r_events =
  let* edn = Option.to_result ~none:(msgf "Unknown endpoint") peer.edn in
  let* pkt = Zostera.send ~now session data in
  let peer =
    if not (String.is_empty data) && Option.is_none peer.new_handshake_at
    then { peer with new_handshake_at= Some (now + _KEEPALIVE_TIMEOUT + _REKEY_TIMEOUT) }
    else peer in
  Ok ({ peer with last_sent= Some now; keepalive_at= None }, `Send (edn, pkt) :: r_events)

let flush ~now ~keepalive peer r_events =
  match peer.curr with
  | None -> (peer, r_events)
  | Some curr ->
    match Q.to_list peer.queue with
    | [] when keepalive ->
      begin match send ~now peer curr "" r_events with
      | Ok value -> value
      | Error err -> peer, `Error err :: r_events end
    | [] -> (peer, r_events)
    | sstr ->
      let rec go peer r_events = function
        | [] -> peer, r_events
        | data :: rem as sstr ->
          match send ~now peer curr data r_events with
          | Ok (peer, r_events) -> go peer r_events rem
          | Error err ->
            (* NOTE(dinosaure): it's safe because [sstr] comes from [Q.to_list]. *)
            { peer with queue= Q.unsafe_of_list sstr }, `Error err :: r_events in
      go { peer with queue= Q.empty } r_events sstr

let on_msg2 t ~now ~load ~from uid peer pkt =
  let* out = Zostera.msg2_of_string ?g:t.g t.bakery t.limiter ~now ~load ~peer:from pkt in
  match out, peer.handshake with
  | `Cookie pkt, _ -> Ok (peer, [ `Send (from, pkt) ])
  | `Msg2 _, None -> error_msgf "Unexpected handshake response"
  | `Msg2 msg2, Some { state; _ } ->
    let* () = guard ~err:(msgf "Unexpected receiver") @@ fun () ->
      Zostera.uid_of_initiator state = uid in
    let* session = Zostera.step2 ~now msg2 t.identity state in
    let peer = { peer with edn= Some from; last_recv= Some now; new_handshake_at= None } in
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
      | None, Some (Current curr) -> Some (Confirmed curr)
      | None, None -> None in
    let peer = { peer with prev; curr= Some (Current session); next= None
                         ; handshake= None; last_handshake= Some now
                         ; zero_keys_at= Some (now + 3 * _REJECT_AFTER_TIME) } in
    let peer, r_events = flush ~now ~keepalive:true peer forget in
    Ok (peer, r_events)

let on_cookie ~now uid peer pkt =
  let* () = guard ~err:(msgf "Unexpected cookie") @@ fun () ->
    uid_of_session `Hshk peer = Some uid
    || uid_of_session `Next peer = Some uid in
   let* () = Zostera.consume_cookie peer.remote ~now ~uid pkt in
   Ok (peer, [])

(* NOTE(dinosaure): here, we rotate sessions:
   - the [t.curr] session becomes [t.prev]
   - the given session is new new [t.curr] session
   - [t.next] becomes [None] in any cases

   TODO(dinosaure): it seems that when we have a next, it becomes the previous.*)
let rotate ~now peer session =
  let forget = cons_if_some (uid_of_session `Prev peer) [] in
  let forget = List.map (fun uid -> `Forget uid) forget in
  let prev = match peer.curr with
    | Some (Current curr) -> Some (Confirmed curr)
    | None -> None in
  let peer = { peer with prev; curr= Some (Current session); next= None } in
  flush ~now ~keepalive:false peer forget

(* See [timers.go]/[JitterMaxMs]. *)
let jitter t =
  let buf = Mirage_crypto_rng.generate ?g:t.g 2 in
  (String.get_uint16_le buf 0 mod 334) * 1_000_000 (* [0, 333] ms *)

let initiation t ~timestamp ~now ~first peer edn r_events =
  let uid = fresh t in
  let* state, msg1 = Zostera.step0 ?g:t.g ~uid ~timestamp t.identity peer.remote in
  let pkt = Zostera.msg1_to_string ~now state msg1 in
  (* NOTE(dinosaure): WireGuard mentions an exponential backoff instead of
     [_REKEY_TIMEOUT]. *)
  let retry_at = now + _REKEY_TIMEOUT + jitter t in
  let handshake = Some { state; first; retry_at } in
  let peer =
    { peer with handshake
         ; last_sent= Some now; last_handshake_sent= Some now
         ; keepalive_at= None } in
  Ok (peer, `Send (edn, pkt) :: `Register uid :: r_events)

let recently_sent_handshake peer now =
  match peer.last_handshake_sent with
  | Some sent -> now - sent < _REKEY_TIMEOUT
  | None -> false

let initiate t ~timestamp ~now peer r_events =
  match peer.handshake, peer.edn with
  | Some _, _ -> Ok (peer, r_events) (* NOTE(dinosaurte): already in-handshake *)
  | None, _ when recently_sent_handshake peer now -> Ok (peer, r_events) (* NOTE(dinosaure): already sent [msg1]/[msg2] the last 5s. *)
  | None, None -> error_msgf "Unknown endpoint"
  | None, Some edn ->
    (* "if a handshake response message is not subsequently received after
        [_REKEY_TIMEOUT] seconds, a new handshake initiation message is
        constructed and sent." (§ 6.4). See also [retransmit]. *)
    initiation t ~timestamp ~now ~first:now peer edn r_events

let maybe_rekey_on_recv t ~timestamp ~now peer r_events =
  match peer.curr with
  | None -> peer, r_events
  | Some (Current curr) ->
    match Zostera.role curr with
    | Zostera.Initiator when Zostera.rekey_on_recv ~now curr ->
      begin match initiate t ~timestamp ~now peer r_events with
      | Ok value -> value
      | Error err -> peer, `Error err :: r_events end
    | Zostera.Initiator | Zostera.Responder -> peer, r_events

let on_data t ~timestamp ~now ~from uid peer pkt =
  let* peer, out, r_events = match peer with
    | { next= Some next; _ } when Zostera.uid_of_local next = uid ->
      let* session, out = Zostera.confirm ~now next pkt in
      let peer = { peer with edn= Some from; last_recv= Some now; new_handshake_at= None } in
      let peer, r_events = rotate ~now peer session in
      Ok (peer, out, r_events)
    | { curr= Some (Current curr); _ } when Zostera.uid_of_local curr = uid ->
      let* out = Zostera.recv ~now curr pkt in
      let peer = { peer with edn= Some from; last_recv= Some now; new_handshake_at= None } in
      Ok (peer, out, [])
    | { prev= Some (Confirmed prev); _ } when Zostera.uid_of_local prev = uid ->
      let* out = Zostera.recv ~now prev pkt in
      let peer = { peer with edn= Some from; last_recv= Some now; new_handshake_at= None } in
      Ok (peer, out, [])
    | { prev= Some (Unconfirmed prev); _ } when Zostera.uid_of_local prev = uid ->
      let* session, out = Zostera.confirm ~now prev pkt in
      let peer = { peer with edn= Some from; last_recv= Some now; new_handshake_at= None } in
      Ok ({ peer with prev= Some (Confirmed session) }, out, [])
    | _ -> error_msgf "Unexpected receiver" in
  let peer, r_events = match out with
    | `Keepalive -> peer, r_events
    | `Data data ->
      let peer =
        if Option.is_none peer.keepalive_at
        then { peer with keepalive_at= Some (now + _KEEPALIVE_TIMEOUT) }
        else peer in
      let r_events = `Deliver (Zostera.public_of_remote peer.remote, data) :: r_events in
      peer, r_events in
  let peer, r_events = maybe_rekey_on_recv t ~timestamp ~now peer r_events in
  Ok (peer, r_events)

let packet t ~timestamp ~now ~load ~from pkt =
  let* k =
    let* () = guard ~err:(msgf "Truncated WireGuard packet") @@ fun () ->
      String.length pkt >= 4 in
    Ok (String.get_int32_le pkt 0) in
  match k with
  | 1l -> on_msg1 t ~now ~load ~from pkt
  | 2l | 3l | 4l ->
    let* uid = Uid.receiver pkt in
    let* key = Option.to_result ~none:(msgf "Unknown receiver") (Hashtbl.find_opt t.index uid) in
    let* peer = Option.to_result ~none:(msgf "Orphan unique ID") (Hashtbl.find_opt t.peers key) in
    let* peer, r_events = match k with
      | 2l -> on_msg2 t ~now ~load ~from uid peer pkt
      | 3l -> on_cookie ~now uid peer pkt
      | _ -> on_data t ~timestamp ~now ~from uid peer pkt in
    Ok (apply t peer (List.rev r_events))
  | _ -> error_msgf "Unknown packet type"

(* Out *)

let maybe_rekey_on_send t ~timestamp ~now peer r_events =
  match peer.curr with
  | Some (Current curr) when Zostera.rekey_on_send ~now curr ->
    begin match initiate t ~timestamp ~now peer r_events with
    | Ok value -> value
    | Error err -> peer, `Error err :: r_events end
  | Some _ | None -> peer, r_events

(* About [enqueue] and [write], § 6.4:

   > The first time the user sends a packet over a WireGuard interface, the
   > packet cannot immediately be sent, because no current session exists. So,
   > after queuing the packet, WireGuard sends a handshake initiation message.
*)
let enqueue t ~timestamp ~now peer data r_events =
  let queue, dropped = Q.push data peer.queue in
  let peer = { peer with queue } in
  let r_events = match dropped with
    | Some x -> `Drop (Zostera.public_of_remote peer.remote, x) :: r_events
    | None -> r_events in
  match initiate t ~timestamp ~now peer r_events with
  | Ok value -> value
  | Error err -> peer, `Error err :: r_events

let write t ~timestamp ~now public = function
  | "" -> Ok []
  | data ->
    let key = Zostera.octets_of_public public in
    let* peer = Option.to_result ~none:(msgf "Unknown peer") (Hashtbl.find_opt t.peers key) in
    let peer, r_events = match peer.curr with
      | Some (Current session as curr) when not (Zostera.expired ~now session) ->
        (* NOTE(dinosaure): we can have an error due to:
           - [peer.edn] is not set
           - the session is expired (which should not occur), see [expired]
           - the session is exhausted (which should not occur), see [expired] *)
        begin match send ~now peer curr data [] with
        | Ok (peer, r_events) -> maybe_rekey_on_send t ~timestamp ~now peer r_events
        | Error _ -> enqueue t ~timestamp ~now peer data [] end
      | Some _ | None -> enqueue t ~timestamp ~now peer data [] in
    Ok (apply t peer (List.rev r_events))

(* Tick *)

let drop peer r_events =
  let public = Zostera.public_of_remote peer.remote in
  let fn r_events data = `Drop (public, data) :: r_events in
  let r_events = List.fold_left fn r_events (Q.to_list peer.queue) in
  ({ peer with queue= Q.empty }, r_events)

(* § 6.3:
   > If no new secure session is created after [_REJECT_AFTER_TIME × 3]
   > seconds, the current secure session, the previous secure session, and
   > potentially the next secure session are discarded and zeroed out, in
   > addition to any possible partially-completed handshake states and
   > ephemeral keys. *)
let zero_keys peer r_events =
  let forget = List.map (fun uid -> `Forget uid) (uids peer) in
  let peer, r_events = drop peer (List.rev_append forget r_events) in
  let peer = { peer with prev= None; curr= None; next= None; handshake= None
                    ; keepalive_at= None; new_handshake_at= None; zero_keys_at= None } in
  (peer, r_events)

let give_up peer r_events =
  let r_events = cons_if_some (Option.map forget (uid_of_session `Hshk peer)) r_events in
  let peer, r_events = drop peer r_events in
  { peer with handshake= None; keepalive_at= None }, r_events

let retransmit t ~timestamp ~now peer hshk r_events =
  let r_events = `Forget (Zostera.uid_of_initiator hshk.state) :: r_events in
  let peer = { peer with handshake= None } in
  match peer.edn with
  | None -> peer, `Error (msgf "Unknown endpoint") :: r_events
  | Some edn ->
    match initiation t ~timestamp ~now ~first:hshk.first peer edn r_events with
    | Ok value -> value
    | Error err -> peer, `Error err :: r_events

let passive_keepalive ~now peer r_events =
  let peer = { peer with keepalive_at= None } in
  match peer.curr with
  | Some (Current session as curr) when not (Zostera.expired ~now session) ->
    begin match send ~now peer curr "" r_events with
    | Ok value -> value
    | Error err -> peer, `Error err :: r_events end
  | _ -> peer, r_events

let due now = function Some at -> now >= at | None -> false

let tick t ~timestamp ~now peer =
  let r_events = [] in
  if due now peer.zero_keys_at then zero_keys peer r_events
  else
    let peer, r_events = match peer.handshake with
      | Some hshk when now >= hshk.retry_at ->
        if now - hshk.first >= _REKEY_ATTEMPT_TIME
        then give_up peer r_events
        else retransmit t ~timestamp ~now peer hshk r_events
      | _ -> peer, r_events in
    (* § 6.5:
       > If a peer has received has received a validly-authenticated transport
       > data message, but does not have any packets itself to send back for
       > [_KEEPALIVE_TIMEOUT] seconds, it sends a _keepalive message_.

       [keepalive_at] is armed only when we receive data (see [on_data]).
       It sets to [None] on:
       - [on_msg1] after an authenticated [msg1] (responder)
       - on [send] (if we have no failures) (initiator & responder)
       - on [initiation] (if we have no failures) (initiator) *)
    let peer, r_events =
      if due now peer.keepalive_at
      then passive_keepalive ~now peer r_events
      else peer, r_events in
    if due now peer.new_handshake_at
    then
      let peer = { peer with new_handshake_at= None } in
      match initiate t ~timestamp ~now peer r_events with
      | Ok value -> value
      | Error err -> peer, `Error err :: r_events
    else peer, r_events

let tick t ~timestamp ~now =
  let peers = Hashtbl.fold (fun _ peer acc -> peer :: acc) t.peers [] in
  let fn peer =
    let peer, r_events = tick t ~timestamp ~now peer in
    apply t peer (List.rev r_events) in
  List.concat_map fn peers

let deadlines peer =
  List.filter_map Fun.id
    [ Option.map (fun hshk -> hshk.retry_at) peer.handshake
    ; peer.keepalive_at
    ; peer.new_handshake_at
    ; peer.zero_keys_at ]

let deadline t =
  let fn1 acc at = match acc with
    | None -> Some at
    | Some best -> Some (Int.min best at) in
  let fn0 _ peer acc = List.fold_left fn1 acc (deadlines peer) in
  Hashtbl.fold fn0 t.peers None
