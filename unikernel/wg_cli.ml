let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

type cfg =
  { identity : Zostera.t
  ; peer : Zostera.public
  ; psk : Zostera.psk option
  ; edn : Zostera.Addr.t
  ; keepalive : int option
  ; port : int
  ; address : Ipaddr.V4.t
  ; allowed : Ipaddr.V4.Prefix.t list
  ; mtu : int }

open Cmdliner

let docs_wireguard = "WIREGUARD"

let key =
  let parser str =
    match Base64.decode str with
    | Ok key when String.length key = 32 -> Ok key
    | Ok _ -> Error (`Msg "A WireGuard key must be 32 bytes")
    | Error _ as err -> err in
  let pp ppf key = Fmt.string ppf (Base64.encode_string key) in
  Arg.conv (parser, pp)

let private_key =
  let doc = "Our private key (as $(b,wg genkey) generates)." in
  let open Arg in
  required
  & opt (some key) None
  & info [ "private-key" ] ~doc ~docs:docs_wireguard ~docv:"KEY"

let peer_public_key =
  let doc = "The public key of the WireGuard server." in
  let open Arg in
  required
  & opt (some key) None
  & info [ "peer-public-key" ] ~doc ~docs:docs_wireguard ~docv:"KEY"

let preshared_key =
  let doc = "An optional pre-shared key (as $(b,wg genpsk) generates)." in
  let open Arg in
  value
  & opt (some key) None
  & info [ "preshared-key" ] ~doc ~docs:docs_wireguard ~docv:"KEY"

let endpoint =
  let doc = "The endpoint (IP address and port) of the WireGuard server." in
  let pp ppf { Zostera.Addr.ipaddr; port } = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port in
  let addr = Arg.conv (Zostera.Addr.of_string ~port:51820, pp) in
  let open Arg in
  required
  & opt (some addr) None
  & info [ "endpoint" ] ~doc ~docs:docs_wireguard ~docv:"IPADDR:PORT"

let persistent_keepalive =
  let doc =
    "Send a keepalive to the server every $(docv) seconds (useful when we are \
     behind a NAT). It also initiates the handshake as soon as the unikernel \
     starts."
  in
  let open Arg in
  value
  & opt (some int) None
  & info [ "persistent-keepalive" ] ~doc ~docs:docs_wireguard ~docv:"SECONDS"

let listen_port =
  let doc = "The local UDP port used to talk with the WireGuard server." in
  let open Arg in
  value
  & opt int 51820
  & info [ "listen-port" ] ~doc ~docs:docs_wireguard ~docv:"PORT"

let address =
  let doc = "Our address into the tunnel (given by the WireGuard server)." in
  let ipv4 = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  let open Arg in
  required
  & opt (some ipv4) None
  & info [ "address" ] ~doc ~docs:docs_wireguard ~docv:"IPV4"

let allowed_ips =
  let doc =
    "Destinations which are routed through the tunnel. It is also the set of \
     sources accepted from the server."
  in
  let cidr4 = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  value
  & opt (list cidr4) [ Ipaddr.V4.Prefix.global ]
  & info [ "allowed-ips" ] ~doc ~docs:docs_wireguard ~docv:"CIDRV4,..."

let mtu =
  let doc = "The MTU of the tunnel (TCP MSS are clamped according to it)." in
  let open Arg in
  value
  & opt int 1420
  & info [ "mtu" ] ~doc ~docs:docs_wireguard ~docv:"MTU"

let setup secret peer psk edn keepalive port address allowed mtu =
  let ( let* ) = Result.bind in
  let* identity = Zostera.of_octets secret
    |> Result.map_error (fun err -> msgf "%a" Zostera.pp_error err) in
  let peer = Zostera.public_of_octets peer in
  let psk = Option.map Zostera.psk psk in
  let* () =
    if mtu >= 68 && mtu <= 0xffff then Ok ()
    else Error (`Msg "The MTU of the tunnel must be between 68 and 65535") in
  Ok { identity; peer; psk; edn; keepalive; port; address; allowed; mtu }

let setup =
  let open Term in
  const setup $ private_key $ peer_public_key $ preshared_key $ endpoint
     $ persistent_keepalive $ listen_port $ address $ allowed_ips $ mtu
  |> term_result ~usage:false


