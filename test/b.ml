let _1s = 1_000_000_000
let epoch = 1_700_000_000 * _1s
let timestamp now = epoch + now

type node =
  { bruit : Bruit.t
  ; identity : Zostera.t
  ; addr : Zostera.Addr.t
  ; public : Zostera.public }

let node ipaddr =
  let identity = Zostera.gen () in
  let addr = Zostera.Addr.of_string_exn ipaddr ~port:1234 in
  { bruit= Bruit.create identity; identity; addr; public= Zostera.public identity }

let pair ?persistent_keepalive ~now () =
  (* NOTE(dinosaure): [a] (as an initiator) would like to talk to [b] (a
     responder). We register [a] as a possible peer for [b] and add [b] as node
     to talk to for [a]. *)
  let a = node "10.0.0.1" and b = node "10.0.0.2" in
  let _ =
    Bruit.add b.bruit ~timestamp:(timestamp now) ~now a.public
    |> Result.get_ok in
  let actions =
    Bruit.add ?persistent_keepalive ~edn:b.addr a.bruit
      ~timestamp:(timestamp now) ~now b.public
    |> Result.get_ok in
  (a, b, actions)

type trace =
  { sent : (Zostera.Addr.t * int * int) list (* src, kind, length *)
  ; delivered : (Zostera.Addr.t * string) list (* receiver, data *)
  ; dropped : string list }

let padded str =
  let len = String.length str in
  str ^ String.make ((16 - (len mod 16)) land 15) '\000'

let _MSG1 = 1 and _MSG2 = 2 and _DATA = 4 and _COOKIE = 3
let _KEEPALIVE_LEN = 32
let kind pkt = String.get_uint8 pkt 0

let run ?(lose = fun _src _pkt -> false) ~now nodes src actions =
  let sent = ref [] and delivered = ref [] and dropped = ref [] in
  let rec go src actions =
    let fn = function
      | `Send (dst, _ds, pkt) ->
        sent := (src.addr, kind pkt, String.length pkt) :: !sent;
        if not (lose src pkt) then begin
          match List.find_opt (fun n -> n.addr = dst) nodes with
          | None -> ()
          | Some node ->
            match Bruit.packet node.bruit ~timestamp:(timestamp now) ~now
                    ~from:src.addr pkt with
            | Ok actions -> go node actions
            | Error err -> Test.failwithf "%a" Zostera.pp_error err end
      | `Deliver (_, data) -> delivered := (src.addr, data) :: !delivered
      | `Drop (_, data) -> dropped := data :: !dropped
      | `Error err -> Test.failwithf "%a" Zostera.pp_error err in
    List.iter fn actions in
  go src actions;
  { sent= List.rev !sent; delivered= List.rev !delivered; dropped= List.rev !dropped }

let write ?lose ~now nodes src dst data =
  match Bruit.write src.bruit ~timestamp:(timestamp now) ~now dst.public data with
  | Ok actions -> run ?lose ~now nodes src actions
  | Error err -> Test.failwithf "%a" Zostera.pp_error err

let tick ?lose ~now nodes src =
  run ?lose ~now nodes src (Bruit.tick src.bruit ~timestamp:(timestamp now) ~now)

let count ~src ~kind:k trace =
  List.length (List.filter (fun (src', k', _) -> src' = src.addr && k' = k) trace.sent)

let handshake ~now a b =
  let trace = write ~now [ a; b ] a b "hello" in
  Test.check (trace.delivered = [ (b.addr, padded "hello") ]);
  Test.check (count ~src:a ~kind:_MSG1 trace = 1);
  Test.check (count ~src:b ~kind:_MSG2 trace = 1)

let test001 =
  let descr = {text|handshake and staged packets|text} in
  Test.test ~title:"test001" ~descr @@ fun () ->
  let now = 1_000 * _1s in
  let a, b, _ = pair ~now () in
  (* NOTE(dinosaure): initiate a WireGuard connection between [a] to [b]. *)
  handshake ~now a b;
  (* NOTE(dinosaure): the responder [b] can talk now to [a]. *)
  let trace = write ~now [ a; b ] b a "world" in
  Test.check (trace.delivered = [ (a.addr, padded "world") ])

let test002 =
  let descr = {text|passive keepalive|text} in
  Test.test ~title:"test002" ~descr @@ fun () ->
  let now = 1_000 * _1s in
  let a, b, _ = pair ~now () in
  handshake ~now a b;
  (* [b] received data but we don't send back. We do nothing for 9s. *)
  let trace = tick ~now:(now + 9 * _1s) [ a; b ] b in
  Test.check (trace.sent = []);
  (* after 10s, we should send a keepalive. *)
  let trace = tick ~now:(now + 10 * _1s) [ a; b ] b in
  Test.check (trace.sent = [ (b.addr, _DATA, _KEEPALIVE_LEN) ]);
  Test.check (trace.delivered = []); (* Silence is a virtue. *)
  let trace = tick ~now:(now + 20 * _1s) [ a; b ] a in
  Test.check (trace.sent = []) (* Again, silence is a virtue! *)

let test003 =
  let descr = {text|new handshake after timeouts|text} in
  Test.test ~title:"test003" ~descr @@ fun () ->
  let now = 1_000 * _1s in
  let a, b, _ = pair ~now () in
  handshake ~now a b;
  let _ = tick ~now:(now + 10 * _1s) [ a; b ] b in (* keepalive *)
  let lose src _pkt = src.addr = b.addr in (* lose responder's packets *)
  let now = now + 30 * _1s in
  let _ = write ~lose ~now [ a; b ] a b "hého!" in
  let trace = tick ~lose ~now:(now + 14 * _1s) [ a; b ] a in
  Test.check (count ~src:a ~kind:_MSG1 trace = 0);
  let trace = tick ~lose ~now:(now + 15 * _1s + 334_000_000) [ a; b ] a in
  (* our initiator retry an handshake after _KEEPALIVE_TIMEOUT + _REKEY_TIMEOUT + jitter (<= 333ms) *)
  Test.check (count ~src:a ~kind:_MSG1 trace = 1)

let test004 =
  let descr = {text|one handshake and black hole|text} in
  Test.test ~title:"test004" ~descr @@ fun () ->
  let now = ref (1_000 * _1s) in
  let a, b, _ = pair ~now:!now () in
  (* handshake is done! *)
  let lose _ _ = true in
  let trace = write ~lose ~now:!now [ a; b ] a b "and we loose everything!" in
  let msg1 = ref (count ~src:a ~kind:_MSG1 trace) in
  Test.check (!msg1 = 1);
  let dropped = ref [] in
  while !dropped = [] do
    match Bruit.deadline a.bruit with
    | None -> Test.failwithf "We must have, at least, one deadline"
    | Some at ->
      now := at; (* we advance *)
      let trace = tick ~lose ~now:!now [ a; b ] a in
      msg1 := !msg1 + count ~src:a ~kind:_MSG1 trace;
      dropped := trace.dropped
  done;
  Test.check (!msg1 = 20); (* all of our attempts: 18 (_MAX_TIMER_HANDSHAKES + 2) *)
  Test.check (!dropped = [ "and we loose everything!" ]);
  Test.check (Bruit.deadline a.bruit = Some (!now + 540 (* _REJECT_AFTER_TIME * 3 *) * _1s))

let test005 =
  let descr = {text|last minute handshake|text} in
  Test.test ~title:"test005" ~descr @@ fun () ->
  let now = 1_000 * _1s in
  let a, b, _ = pair ~now () in
  handshake ~now a b;
  let lose src pkt = src.addr = a.addr && kind pkt = _MSG1 in
  let trace = write ~lose ~now:(now + 160 * _1s) [ a; b ] b a "before" in
  Test.check (count ~src:a ~kind:_MSG1 trace = 0);
  let trace = write ~lose ~now:(now + 166 * _1s) [ a; b ] b a "after" in
  Test.check (count ~src:a ~kind:_MSG1 trace = 1); (* our last minute handshake *)
  let trace = write ~lose ~now:(now + 172 * _1s) [ a; b ] b a "not too late" in
  Test.check (trace.delivered = [ (a.addr, padded "not too late") ]);
  Test.check (count ~src:a ~kind:_MSG1 trace = 0);
  let trace = write ~lose ~now:(now + 190 * _1s) [ a; b ] a b "too late" in
  Test.check (count ~src:a ~kind:_MSG1 trace = 1);
  Test.check (count ~src:a ~kind:_DATA trace = 0);
  Test.check (trace.delivered = [])

let test006 =
  let descr = {text|persistent keepalive|text} in
  Test.test ~title:"test006" ~descr @@ fun () ->
  let now = 1_000 * _1s in
  let a, b, actions = pair ~persistent_keepalive:25 ~now () in
  let trace = run ~now [ a; b ] a actions in
  Test.check (count ~src:a ~kind:_MSG1 trace = 1);
  Test.check (count ~src:a ~kind:_DATA trace = 1);
  for i = 1 to 3 do
    let now = now + (i * 25 * _1s) in
    let trace = tick ~now:(now - 1) [ a; b ] a in
    Test.check (trace.sent = []);
    let trace = tick ~now [ a; b ] a in
    (* A keepalive every 25s *)
    Test.check (trace.sent = [ a.addr, _DATA, _KEEPALIVE_LEN ])
  done

let ( / ) = Filename.concat

let () =
  Mirage_crypto_rng_unix.use_default ();
  let tests = [ test001; test002; test003; test004; test005; test006 ] in
  let ({ Test.directory } as runner) = Test.runner (Sys.getcwd () / "_tests") in
  let run idx test =
    Format.printf "test%03d: %!" (succ idx);
    Test.run runner test;
    Format.printf "ok\n%!"
  in
  Format.printf "Run tests into %s\n%!" directory;
  List.iteri run tests
