let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let run () =
  Mirage_crypto_rng_unix.use_default ();
  let now () = int_of_float (Unix.gettimeofday () *. 1e9) in
  let i = Zostera.gen () in
  let r = Zostera.gen () in
  let* init0, msg1 = Zostera.step0 ~now i (snd r) in
  let* responder, msg2 = Zostera.step1 msg1 r in
  let* init1 = Zostera.step2 msg2 i init0 in
  let (_Ai, _Bi) = Zostera.keys init1 in
  let (_Ar, _Br) = Zostera.keys responder in
  if _Ai = _Ar && _Bi = _Br
  then Ok () else error_msgf "Handshake failure"

let () = match run () with
  | Ok () -> ()
  | Error err -> Fmt.epr "%s: %a\n%!" Sys.executable_name Zostera.pp_error err
