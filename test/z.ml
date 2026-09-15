let test00 =
  let descr = {text|tai64n|text} in
  Test.test ~title:"test00" ~descr @@ fun () ->
  let str0 = Zostera.tai64n ~now:(Fun.const 0) in
  Test.check (str0 = "\x40\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00");
  let _10ns = 10 in
  let _10us = 10_000 in
  let _1ms = 1_000_000 in
  let _10ms = 10_000_000 in
  let _20ms = 20_000_000 in
  let tests =
    [ (_10ns, false); (_10us, false); (_1ms, false); (_10ms, false)
    ; (_20ms, true) ] in
  let str0 = Zostera.tai64n ~now:(Fun.const 123456789) in
  let fn (ns, expected) =
    let ns = 123456789 + ns in
    let str = Zostera.tai64n ~now:(Fun.const ns) in
    Test.check (Eqaf.compare_be str0 str < 0 = expected) in
  List.iter fn tests

let ( / ) = Filename.concat

let () =
  let tests = [ test00 ] in
  let ({ Test.directory } as runner) = Test.runner (Sys.getcwd () / "_tests") in
  let run idx test =
    Format.printf "test%03d: %!" (succ idx);
    Test.run runner test;
    Format.printf "ok\n%!"
  in
  Format.printf "Run tests into %s\n%!" directory;
  List.iteri run tests
