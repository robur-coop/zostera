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

let test01 =
  let descr = {text|limiter|text} in
  Test.test ~title:"test01" ~descr @@ fun () ->
  let process =
    [| (true, None, "initial burst")
     ; (true, None, "initial burst")
     ; (true, None, "initial burst")
     ; (true, None, "initial burst")
     ; (true, None, "initial burst")
     ; (false, None, "after burst")
     ; (true, Some 50_000_000, "filling tokens for single packet")
     ; (false, None, "not having refilled enough")
     ; (true, Some 100_000_000, "filling tokens for two packet burst")
     ; (true, None, "second packet in 2 packet burst")
     ; (false, None, "packet following 2 packet burst") |] in
  let ipaddrs =
    let port = 1234 in
    Zostera.Addr.[ of_string_exn "127.0.0.1" ~port
                 ; of_string_exn "192.168.1.1" ~port 
                 ; of_string_exn "172.167.2.3" ~port
                 ; of_string_exn "97.231.252.215" ~port
                 ; of_string_exn "248.97.91.167" ~port
                 ; of_string_exn "188.208.233.47" ~port
                 ; of_string_exn "104.2.183.179" ~port
                 ; of_string_exn "72.129.46.120" ~port
                 ; of_string_exn "2001:0db8:0a0b:12f0:0000:0000:0000:0001" ~port
                 ; of_string_exn "f5c2:818f:c052:655a:9860:b136:6894:25f0" ~port
                 ; of_string_exn "b2d7:15ab:48a7:b07c:a541:f144:a9fe:54fc" ~port
                 ; of_string_exn "a47b:786e:1671:a22b:d6f9:4ab0:abc7:c918" ~port
                 ; of_string_exn "ea1e:d155:7f7a:98fb:2bf5:9483:80f6:5445" ~port
                 ; of_string_exn "3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4" ~port ] in
  let now = ref 0 in
  let limiter = Zostera.Limiter.create () in
  for idx = 0 to Array.length process - 1 do
    let allowed, wait, _txt = process.(idx) in
    incr now;
    Option.iter (fun ns -> now := !now + ns) wait;
    let res = ref true in
    let fn addr =
      let value = Zostera.Limiter.allow limiter ~now:(Fun.const !now) addr in
      res := !res && (allowed = value) in
    List.iter fn ipaddrs;
    Test.check !res
  done

let ( / ) = Filename.concat

let () =
  let tests = [ test00; test01 ] in
  let ({ Test.directory } as runner) = Test.runner (Sys.getcwd () / "_tests") in
  let run idx test =
    Format.printf "test%03d: %!" (succ idx);
    Test.run runner test;
    Format.printf "ok\n%!"
  in
  Format.printf "Run tests into %s\n%!" directory;
  List.iteri run tests
