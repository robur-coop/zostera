module RNG = Mirage_crypto_rng.Fortuna

let rng =
  let fn () = Mirage_crypto_rng_mkernel.initialize (module RNG) in
  let finally = Mirage_crypto_rng_mkernel.kill in
  Mkernel.map fn Mkernel.[] |> Mkernel.finally finally

let run _quiet (cidr4, gateway4) private_cidr _metrics =
  let outer = Outer.device ~name:"service" ?gateway:gateway4 cidr4 in
  let inner = Inner.device ~name:"private" private_cidr in
  Mkernel.(run [ rng; outer; inner; _metrics ])
  @@ fun _rng _outer _inner _metrics () ->
  assert false

open Cmdliner

let docs_metrics = "METRICS"
let docs_private = "PRIVATE NETWORK"

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

let name =
  let doc = "The name of the unikernel." in
  let open Arg in
  value
  & opt string "wg"
  & info [ "name" ] ~doc ~docs:docs_metrics ~docv:"NAME"

let setup_metrics ipv4 gateway dst name =
  let cfg = Option.map (fun ipv4 -> (ipv4, gateway)) ipv4 in
  let dst, port =
    match dst with
    | Some (dst, port) -> (Some dst, Some port)
    | None -> (None, None)
  in
  Tally_mnet.device ~device:"metrics" ~name cfg ?port dst

let setup_metrics =
  let open Term in
  const setup_metrics $ metrics_ipv4 $ metrics_ipv4_gateway $ metrics $ name

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
  $ setup_service
  $ private_ipv4
  $ setup_metrics

let cmd =
  let doc = "A WireGuard client as a gateway for a private network." in
  let info = Cmd.info "wg" ~doc in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
