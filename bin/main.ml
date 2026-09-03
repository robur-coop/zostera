let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let peer0 = Zostera.addr_of_string_exn ~port:1234 "1.2.3.4:5678"
let peer1 = Zostera.addr_of_string_exn ~port:1234 "4.3.2.1:5678"

type entry = { psk : Zostera.psk option; mutable last : Zostera.timestamp option }
let peers : (string, entry) Hashtbl.t = Hashtbl.create 0x10

let authorize public timestamp =
  match Hashtbl.find_opt peers (Zostera.octets_of_public public) with
  | None -> `Reject
  | Some entry ->
    let fresh = match entry.last with
      | None -> true
      | Some last -> Zostera.newer timestamp last in
    if not fresh then `Reject
    else begin entry.last <- Some timestamp; `Accept entry.psk end

let run () =
  Mirage_crypto_rng_unix.use_default ();
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  let i = Zostera.gen () in
  let q = Zostera.psk (String.make 32 '\x11') in
  Hashtbl.replace peers (Zostera.octets_of_public (Zostera.public i))
    { psk= Some q; last= None };
  let r = Zostera.gen () in
  let limiter_i = Zostera.limiter () in
  let limiter_r = Zostera.limiter () in
  let checker_i = Zostera.checker ~me:i () in
  let checker_r = Zostera.checker ~me:r () in
  let* init0, msg1 = Zostera.step0 ~now i (Zostera.public r) in
  let _mac1, pkt1 = Zostera.pkt_of_initiator init0 (Zostera.public r) msg1 in
  let* (_0, msg1) =
    match Zostera.msg1_of_string checker_r limiter_i ~now ~load:false ~peer:peer0 pkt1 with
    | Ok `Cookie _ -> error_msgf "We would like to emit cookie"
    | Ok (`Msg1 (uid, msg1)) -> Ok (uid, msg1)
    | Error _ as err -> err in
  let* responder, msg2 = Zostera.step1 msg1 ~peer:authorize r in
  let _mac1, pkt = Zostera.pkt_of_responder responder _0 (Zostera.public i) msg2 in
  let* link, msg2 =
    match Zostera.msg2_of_string checker_i limiter_r ~now ~load:false ~peer:peer1 pkt with
    | Ok `Cookie _ -> error_msgf "We would like to emit cookie"
    | Ok (`Msg2 (link, msg2)) -> Ok (link, msg2)
    | Error _ as err -> err in
  let* session0 = Zostera.step2 ~psk:q ~now link msg2 i init0 in
  let { Zostera.send= _Ai; recv= _Bi } = Zostera.keys session0 in
  let { Zostera.recv= _Ar; send= _Br } =
    let session1 = Zostera.session_of_responder ~now _0 responder in
    Zostera.keys session1 in
  if _Ai = _Ar && _Bi = _Br
  then Ok () else error_msgf "Handshake failure"

let () = match run () with
  | Ok () -> ()
  | Error err -> Fmt.epr "%s: %a\n%!" Sys.executable_name Zostera.pp_error err
