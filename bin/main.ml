let () = match Bruit.run () with
  | Ok () -> ()
  | Error err -> Fmt.epr "%s: %a\n%!" Sys.executable_name Bruit.pp_error err
