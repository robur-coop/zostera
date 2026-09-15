[@@@warning "-26-27"]

let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let peer0 = Zostera.Addr.of_string_exn ~port:1234 "1.2.3.4:5678"
let peer1 = Zostera.Addr.of_string_exn ~port:1234 "4.3.2.1:5678"

type entry = { remote: Zostera.remote; mutable last : Zostera.timestamp option }
let peers : (string, entry) Hashtbl.t = Hashtbl.create 0x10
(* [peers] exists on the [r] side (it can exists on both side but may be empty on [i] side) *)

let authorize public =
  match Hashtbl.find_opt peers (Zostera.octets_of_public public) with
  | None -> `Reject
  | Some entry ->
    let set timestamp = entry.last <- Some timestamp in
    `Accept (entry.remote, entry.last, set)

let run_without_cookie () =
  (* we need a monotonic clock *)
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  (* initiate an identity for [i] *)
  let i = Zostera.gen () in
  (* pre-shared key *)
  let q = Zostera.psk (String.make 32 '\x11') in
  (* initiate an identity for [r] *)
  let r = Zostera.gen () in
  (* add the [i] identity on the [r] side with a preshared key [q] *)
  let* rr = Zostera.remote ~psk:q i (Zostera.public r) in
  let* ri = Zostera.remote ~psk:q r (Zostera.public i) in
  Hashtbl.replace peers (Zostera.octets_of_public (Zostera.public i))
    { remote= ri; last= None };
  let limiter_i = Zostera.Limiter.create () in (* ratelimit on [i] *)
  let limiter_r = Zostera.Limiter.create () in (* ratelimit on [r] *)
  let cookie_generator_i = Zostera.Bakery.create ~me:i () in (* cookies generator for [i] *)
  let cookie_generator_r = Zostera.Bakery.create ~me:r () in (* cookies generator for [r] *)
  let* init0, msg1 = Zostera.step0 ~now i rr in
  (* generate the first packet [msg1] *)
  let pkt1 = Zostera.pkt_of_initiator ~now init0 msg1 in
  (* transform the packet to a string, and we give the [mac1] *)
  let* (_0, msg1) =
    (* here, we decode the packet as [r] and get [msg1] *)
    (* [load = true] => [`Cookie _] *)
    match Zostera.msg1_of_string cookie_generator_r limiter_r ~now ~load:false ~peer:peer0 pkt1 with
    | Ok `Cookie _ -> error_msgf "We would like to emit cookie (0)"
    | Ok (`Msg1 (uid, msg1)) -> Ok (uid, msg1)
    | Error _ as err -> err in
  (* here, we compute [msg1] and generate [msg2] *)
  (* we have an association between [peer0] and its public key [Zostera.public i] *)
  (* we also check via [authorize] that the incoming packet corresponds to
     an authorized peer *)
  let* responder, msg2 = Zostera.step1 msg1 ~peer:authorize r in
  (* transform [msg2] to a string *)
  let pkt = Zostera.pkt_of_responder ~now responder _0 msg2 in
  let* link, msg2 =
    (* here, we decode the packet as [i] and get [msg2] *)
    (* [load = true] => [`Cookie _] *)
    match Zostera.msg2_of_string cookie_generator_i limiter_i ~now ~load:false ~peer:peer1 pkt with
    | Ok `Cookie _ -> error_msgf "We would like to emit cookie (1)"
    | Ok (`Msg2 (link, msg2)) -> Ok (link, msg2)
    | Error _ as err -> err in
  (* on the [i], we are able to create a session *)
  let* session0 = Zostera.step2 ~now link msg2 i init0 in
  let { Zostera.send= _Ai; recv= _Bi } = Zostera.keys session0 in
  (* on the [r], we are able to create a session with [_0]/[peer0] *)
  let* session1 = Zostera.session_of_responder ~now _0 responder in
  let { Zostera.recv= _Ar; send= _Br } =
    Zostera.keys session1 in
  (* [i] and [r] shares keys *)
  if _Ai = _Ar && _Bi = _Br
  then Ok () else error_msgf "Handshake failure"

let run_with_cookie () =
  (* we need a monotonic clock *)
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  (* initiate an identity for [i] *)
  let i = Zostera.gen () in
  (* pre-shared key *)
  let q = Zostera.psk (String.make 32 '\x11') in
  (* initiate an identity for [r] *)
  let r = Zostera.gen () in
  (* add the [i] identity on the [r] side with a preshared key [q] *)
  let* rr = Zostera.remote ~psk:q i (Zostera.public r) in
  let* ri = Zostera.remote ~psk:q r (Zostera.public i) in
  Hashtbl.replace peers (Zostera.octets_of_public (Zostera.public i))
    { remote= ri; last= None };
  let limiter_i = Zostera.Limiter.create () in (* ratelimit on [i] *)
  let limiter_r = Zostera.Limiter.create () in (* ratelimit on [r] *)
  let cookie_generator_i = Zostera.Bakery.create ~me:i () in (* cookies generator for [i] *)
  let cookie_generator_r = Zostera.Bakery.create ~me:r () in (* cookies generator for [r] *)
  let* init0, msg1 = Zostera.step0 ~now i rr in
  (* generate the first packet [msg1] *)
  let pkt1 = Zostera.pkt_of_initiator ~now init0 msg1 in
  let* cookie = match Zostera.msg1_of_string cookie_generator_r limiter_r ~now ~load:true ~peer:peer0 pkt1 with
    | Ok (`Cookie cookie) -> Ok cookie
    | Ok (`Msg1 _) -> error_msgf "Unexpected msg1"
    | Error _ as err -> err in
  let* () =
    let uid = Zostera.uid_of_initiator init0 in
    Zostera.consume_cookie rr ~now ~uid cookie in
  let pkt1 = Zostera.pkt_of_initiator ~now init0 msg1 in
  let* (_0, msg1) =
    (* here, we decode the packet as [r] and get [msg1] *)
    (* [load = true] => [`Cookie _] *)
    match Zostera.msg1_of_string cookie_generator_r limiter_r ~now ~load:true ~peer:peer0 pkt1 with
    | Ok (`Cookie cookie) -> error_msgf "We would like to emit cookie (0)"
    | Ok (`Msg1 (uid, msg1)) -> Ok (uid, msg1)
    | Error _ as err -> err in
  (* here, we compute [msg1] and generate [msg2] *)
  (* we have an association between [peer0] and its public key [Zostera.public i] *)
  (* we also check via [authorize] that the incoming packet corresponds to
     an authorized peer *)
  let* responder, msg2 = Zostera.step1 msg1 ~peer:authorize r in
  (* transform [msg2] to a string *)
  let pkt = Zostera.pkt_of_responder ~now responder _0 msg2 in
  let* link, msg2 =
    (* here, we decode the packet as [i] and get [msg2] *)
    (* [load = true] => [`Cookie _] *)
    (* reynir: does it even make sense for [i] to be under load? [i] cannot send a cookie I think *)
    match Zostera.msg2_of_string cookie_generator_i limiter_i ~now ~load:false ~peer:peer1 pkt with
    | Ok `Cookie _ -> error_msgf "We would like to emit cookie (1)"
    | Ok (`Msg2 (link, msg2)) -> Ok (link, msg2)
    | Error _ as err -> err in
  (* on the [i], we are able to create a session *)
  (* look a 6.6:

           when a peer is under load, a handshake initiation message or a handshake
           response message may be discarded and a cookie reply message sent. *)
  (* so even a [i]nitiator can be under load and send a cookie reply to the [r]eceiver *)
  (* I mean, the whitepaper does not do a difference between initiator and receiver when
     it's about cookies. Both (peers) can send such packet. so [i] can also generate and
     send a cookie. *)
  let* session0 = Zostera.step2 ~now link msg2 i init0 in
  let { Zostera.send= _Ai; recv= _Bi } = Zostera.keys session0 in
  (* on the [r], we are able to create a session with [_0]/[peer0] *)
  let* session1 = Zostera.session_of_responder ~now _0 responder in
  let { Zostera.recv= _Ar; send= _Br } =
    Zostera.keys session1 in
  (* [i] and [r] shares keys *)
  if _Ai = _Ar && _Bi = _Br
  then Ok () else error_msgf "Handshake failure"


let () =
  Mirage_crypto_rng_unix.use_default ();
  begin match run_without_cookie () with
  | Ok () -> ()
  | Error err -> Fmt.epr "%s: %a\n%!" Sys.executable_name Zostera.pp_error err end;
  begin match run_with_cookie () with
  | Ok () -> ()
  | Error err -> Fmt.epr "%s: %a\n%!" Sys.executable_name Zostera.pp_error err end
