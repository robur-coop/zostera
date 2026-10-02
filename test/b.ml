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

let _MSG1 = 1 and _MSG2 = 2 and _DATA = 4
let _KEEPALIVE_LEN = 32

let run ?(lose = fun _src _pkt -> false) ~now nodes src actions =
  let kind pkt = String.get_uint8 pkt 0 in
  let sent = ref [] and delivered = ref [] and dropped = ref [] in
  let rec go src actions =
    let fn = function
      | `Send (dst, pkt) ->
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

let ( / ) = Filename.concat

let () =
  Mirage_crypto_rng_unix.use_default ();
  let tests = [ test001 ] in
  let ({ Test.directory } as runner) = Test.runner (Sys.getcwd () / "_tests") in
  let run idx test =
    Format.printf "test%03d: %!" (succ idx);
    Test.run runner test;
    Format.printf "ok\n%!"
  in
  Format.printf "Run tests into %s\n%!" directory;
  List.iteri run tests
