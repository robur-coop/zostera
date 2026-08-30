let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let peer0 =
  let* ipaddr, port = Ipaddr.with_port_of_string ~default:1234 "1.2.3.4:5678" in
  Ok (Zostera.addr ipaddr ~port)

let peer0 = Result.get_ok peer0

let run () =
  Mirage_crypto_rng_unix.use_default ();
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  let _0 = Zostera.uid () in
  let _1 = Zostera.uid () in
  let i = Zostera.gen () in
  let r = Zostera.gen () in
  let limiter = Zostera.limiter () in
  let* init0, msg1 = Zostera.step0 ~now i (Zostera.public r) in
  let checker = Zostera.checker ~me:r () in
  let _mac1, pkt1 = Zostera.pkt_of_initiator init0 _0 (Zostera.public r) msg1 in
  let* (_0, msg1) =
    match Zostera.msg1_of_string checker limiter ~now ~load:false ~peer:peer0 pkt1 with
    | Ok `Cookie _ -> error_msgf "We would like to emit cookie"
    | Ok (`Msg1 (uid, msg1)) -> Ok (uid, msg1)
    | Error _ as err -> err in
  let* responder, msg2 = Zostera.step1 msg1 r in
  let pkt = Zostera.pkt_of_responder responder _0 _1 (Zostera.public i) msg2 in
  let* _, _, msg2 = Zostera.msg2_of_string (Zostera.public i) pkt in
  let* init1 = Zostera.step2 msg2 i init0 in
  let { Zostera.send= _Ai; recv= _Bi } = Zostera.keys init1 in
  let { Zostera.recv= _Ar; send= _Br } = Zostera.keys responder in
  if _Ai = _Ar && _Bi = _Br
  then Ok () else error_msgf "Handshake failure"

let () = match run () with
  | Ok () -> ()
  | Error err -> Fmt.epr "%s: %a\n%!" Sys.executable_name Zostera.pp_error err
