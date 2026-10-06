module SBytes = Slice_bytes

module Events = struct
  type t =
    { queue : event Queue.t
    ; mutable waiter : unit Miou.Computation.t option }
  and event =
    [ `Out of Zostera.Addr.t * int * string
    | `In of SBytes.t
    | `Tick ]

  let create () = { queue= Queue.create (); waiter= None }
  let length t = Queue.length t.queue
  let _MAX_EVENTS = 1014

  let push t ev =
    if Queue.length t.queue < _MAX_EVENTS
    then Queue.push ev t.queue
    else Logs.warn (fun m -> m "Too many events, drop one");
    match t.waiter with
    | None -> ()
    | Some computation ->
      t.waiter <- None;
      ignore (Miou.Computation.try_return computation ())

  let rec pop t =
    match Queue.take_opt t.queue with
    | Some ev -> ev
    | None ->
      let computation = Miou.Computation.create () in
      t.waiter <- Some computation;
      Miou.Computation.await_exn computation;
      pop t
end

let checksum buf ~off ~len =
  let sum = ref 0 in
  for i = 0 to len - 1 do
    let v = Bytes.get_uint8 buf (off + i) in
    sum := !sum + if i land 1 = 0 then v lsl 8 else v
  done;
  while !sum > 0xffff do sum := (!sum land 0xffff) + (!sum lsr 16) done;
  lnot !sum land 0xffff

let too_big buf ~src ~mtu =
  let ihl = (Bytes.get_uint8 buf 0 land 0x0f) * 4 in
  let quoted = Int.min (Bytes.get_uint16_be buf 2) (ihl + 8) in
  let len = 20 + 8 + quoted in
  let pkt = Bytes.make len '\000' in
  Bytes.set_uint8 pkt 0 0x45;
  Bytes.set_uint16_be pkt 2 len;
  Bytes.set_uint8 pkt 8 64;
  Bytes.set_uint8 pkt 9 1;
  Bytes.set_int32_be pkt 12 (Ipaddr.V4.to_int32 src);
  Bytes.blit buf 12 pkt 16 4;
  Bytes.set_uint8 pkt 20 3;
  Bytes.set_uint8 pkt 21 4;
  Bytes.set_uint16_be pkt 26 mtu;
  Bytes.blit buf 0 pkt 28 quoted;
  Bytes.set_uint16_be pkt 22 (checksum pkt ~off:20 ~len:(8 + quoted));
  Bytes.set_uint16_be pkt 10 (checksum pkt ~off:0 ~len:20);
  pkt

let events = Events.create ()

type state =
  { cfg : Wg_cli.cfg
  ; bruit : Bruit.t
  ; nat : Nat.t
  ; outer : Outer.t
  ; inner : Inner.t
  ; rx : bytes
  ; mutable last_expire : int }

let allowed cfg ipaddr = List.exists (Ipaddr.V4.Prefix.mem ipaddr) cfg.Wg_cli.allowed

let run state ~now actions =
  let fn = function
    | `Send (dst, ds, pkt) ->
      Outer.send state.outer ~src_port:state.cfg.port dst ~ds pkt
    | `Deliver (_, buf, len) ->
      let allowed = allowed state.cfg in
      Inner.deliver state.inner state.nat ~allowed ~now buf len
    | `Drop _ -> Logs.debug (fun m -> m "A staged packet was dropped")
    | `Error err -> Logs.warn (fun m -> m "%a" Zostera.pp_error err) in
  List.iter fn actions

let string_of_slice { Slice.buf; off; len } =
  let padded = (len + 15) land (lnot 15) in
  if off = 0 && (Bytes.length buf = len || Bytes.length buf = padded)
  then Bytes.unsafe_to_string buf
  else Bytes.sub_string buf off len

let forward state ~timestamp ~now slice =
  let gateway = Ipaddr.V4.Prefix.address state.inner.Inner.cidr in
  let { Slice.buf; off; _ } = slice in
  match Nat.decode ~off (Bytes.unsafe_to_string buf) with
  | Error _ -> Logs.debug (fun m -> m "Invalid packet from the private network")
  | Ok hdr when Ipaddr.V4.compare hdr.Nat.dst gateway = 0 -> ()
  | Ok hdr when Ipaddr.V4.Prefix.mem hdr.Nat.dst state.inner.Inner.cidr -> ()
  | Ok hdr when not (Ipaddr.V4.Prefix.mem hdr.Nat.src state.inner.cidr) ->
    Logs.warn (fun m -> m "Spoofed source %a from the private network" Ipaddr.V4.pp hdr.Nat.src)
  | Ok hdr when hdr.Nat.len > state.cfg.mtu && hdr.Nat.df ->
    let pkt = too_big buf ~src:gateway ~mtu:state.cfg.mtu in
    Inner.send state.inner hdr.Nat.src (SBytes.make pkt)
  | Ok hdr ->
    let mss = state.cfg.mtu - 40 in
    match Nat.outbound state.nat ~hdr ~now ~mss slice with
    | Error err ->
      Logs.debug (fun m -> m "Drop a packet to %a: %a" Ipaddr.V4.pp hdr.Nat.dst Nat.pp_error err)
    | Ok len ->
      let write slice =
        let data = string_of_slice slice in
        match Bruit.write state.bruit ~timestamp ~now state.cfg.peer data with
        | Ok actions -> run state ~now actions
        | Error err -> Logs.warn (fun m -> m "%a" Zostera.pp_error err) in
      let slice = SBytes.make buf ~off:0 ~len in
      List.iter write (Nat.fragment slice ~mtu:state.cfg.mtu)

let _1ms = 1_000_000

let rec clock events bruit =
  let now = Mkernel.clock_monotonic () in
  let delay = match Bruit.deadline bruit with
    | Some at -> at - now
    | None -> 500 * _1ms in
  Mkernel.sleep (Int.max (10 * _1ms) (Int.min delay (500 * _1ms)));
  Events.push events `Tick;
  clock events bruit

let rec go state =
  let ev = Events.pop events in
  let timestamp = Mkernel.clock_wall () in
  let now = Mkernel.clock_monotonic () in
  begin match ev with
  | `Out (from, ds, pkt) ->
    let pending = Events.length events in
    begin match Bruit.packet_into state.bruit ~timestamp ~now ~pending ~ds ~from pkt state.rx with
    | Ok actions -> run state ~now actions
    | Error err ->
      Logs.debug (fun m -> m "Invalid WireGuard packet from: %a: %a"
        Ipaddr.pp from.Zostera.Addr.ipaddr Zostera.pp_error err) end
  | `In slice -> forward state ~timestamp ~now slice
  | `Tick ->
    run state ~now (Bruit.tick state.bruit ~timestamp ~now);
    if now - state.last_expire > 10_000 * _1ms
    then begin Nat.clean_up state.nat ~now; state.last_expire <- now end
  end;
  go state

module RNG = Mirage_crypto_rng.Fortuna

let rng =
  let fn () = Mirage_crypto_rng_mkernel.initialize (module RNG) in
  let finally = Mirage_crypto_rng_mkernel.kill in
  Mkernel.map fn Mkernel.[] |> Mkernel.finally finally

let run _quiet cfg (cidr4, gateway4) private_cidr _metrics =
  let on_udp from ds pkt = Events.push events (`Out (from, ds, pkt)) in
  let on_ipv4 pkt = Events.push events (`In pkt) in
  let outer = Outer.device ~name:"service" ?gateway:gateway4 ~port:cfg.Wg_cli.port
    ~handler:on_udp cidr4 in
  let inner = Inner.device ~name:"private" ~handler:on_ipv4 private_cidr in
  Mkernel.(run [ rng; outer; inner; _metrics ])
  @@ fun _rng outer inner _metrics () ->
  let bruit = Bruit.create cfg.Wg_cli.identity in
  let nat = Nat.create cfg.address in
  let now = Mkernel.clock_monotonic () in
  let timestamp = Mkernel.clock_wall () in
  let rx = Bytes.create 0x10_000 in
  let state = { cfg; bruit; nat; outer; inner; rx; last_expire= now } in
  Logs.info (fun m -> m "Out public key: %s"
    (Base64.encode_string (Zostera.octets_of_public (Zostera.public cfg.identity))));
  begin match Bruit.add ?psk:cfg.psk ~edn:cfg.edn ?persistent_keepalive:cfg.keepalive
    bruit ~timestamp ~now cfg.peer with
  | Ok actions -> run state ~now actions
  | Error err -> Fmt.failwith "Impossible to add the peer: %a" Zostera.pp_error err end;
  let clock = Miou.async @@ fun () -> clock events bruit in
  let finally () = Miou.cancel clock in
  Fun.protect ~finally @@ fun () ->
  go state

open Cmdliner

let docs_metrics = "METRICS"

let metrics_ipv4 =
  let doc =
    "The IPv4 address (with its prefix) of the metrics interface. If it is not \
     specified (and a metrics destination is given), the metrics interface is \
     configured via a DHCP server."
  in
  let cidr4 = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  value
  & opt (some cidr4) None
  & info [ "metrics-ipv4" ] ~doc ~docs:docs_metrics ~docv:"CIDRV4"

let metrics_ipv4_gateway =
  let doc = "The IPv4 gateway of the metrics interface." in
  let gateway4 = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  let open Arg in
  value
  & opt (some gateway4) None
  & info [ "metrics-ipv4-gateway" ] ~doc ~docs:docs_metrics ~docv:"IPV4"

let metrics =
  let doc =
    "The address of the Telegraf server which collects metrics. If it is not \
     specified, metrics are not reported."
  in
  let pp ppf (ipaddr, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port in
  let addr = Arg.conv (Ipaddr.with_port_of_string ~default:8094, pp) in
  let open Arg in
  value
  & opt (some addr) None
  & info [ "metrics" ] ~doc ~docs:docs_metrics ~docv:"IPADDR"

let name ~default =
  let doc = "The name of the unikernel." in
  let open Arg in
  value
  & opt string default
  & info [ "name" ] ~doc ~docs:docs_metrics ~docv:"NAME"

let setup_metrics ipv4 gateway dst name =
  let cfg = Option.map (fun ipv4 -> (ipv4, gateway)) ipv4 in
  let dst, port =
    match dst with
    | Some (dst, port) -> (Some dst, Some port)
    | None -> (None, None)
  in
  Tally_mnet.device ~device:"metrics" ~name cfg ?port dst

let setup_metrics ~default =
  let open Term in
  const setup_metrics $ metrics_ipv4 $ metrics_ipv4_gateway $ metrics
  $ name ~default

let docs_private = "PRIVATE NETWORK"

let private_ipv4 =
  let doc =
    "Our IPv4 address (with its prefix) on the private network. Hosts on this \
     network must use it as their default gateway."
  in
  let cidr4 = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  required
  & opt (some cidr4) None
  & info [ "private-ipv4" ] ~doc ~docs:docs_private ~docv:"CIDRV4"

let setup_service =
  let open Term in
  const (fun cidr4 gateway4 -> (cidr4, gateway4))
  $ Mnet_cli.ipv4
  $ Mnet_cli.ipv4_gateway

let term =
  let open Term in
  const run
  $ Mnet_cli.setup_logs
  $ Wg_cli.setup
  $ setup_service
  $ private_ipv4
  $ setup_metrics ~default:"wg"

let cmd =
  let doc = "A WireGuard client as a gateway for a private network." in
  let info = Cmd.info "wg" ~doc in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
