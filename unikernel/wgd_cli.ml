let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

type peer =
  { public : Zostera.public
  ; psk : Zostera.psk option
  ; allowed : Ipaddr.V4.Prefix.t list }

type cfg =
  { identity : Zostera.t
  ; peers : peer list (* TODO(dinosaure): use a radix tree here *)
  ; port : int
  ; mtu : int }

open Cmdliner

let docs_wireguard = "WIREGUARD"

let decode_key str =
  match Base64.decode str with
  | Ok key when String.length key = 32 -> Ok key
  | Ok _ -> Error (msgf "A WireGuard key must be 32 bytes")
  | Error _ as err -> err

let peer =
  let ( let* ) = Result.bind in
  let prefixes str =
    let fn acc cidr = match acc, Ipaddr.V4.Prefix.of_string cidr with
      | Ok acc, Ok prefix -> Ok (prefix :: acc)
      | (Error _ as err), _ | _, (Error _ as err) -> err in
    let* allowed = List.fold_left fn (Ok []) (String.split_on_char ',' str) in
    Ok (List.rev allowed) in
  let parser str =
    let* public, allowed, psk = match String.split_on_char ':' str with
      | [ public; allowed ] -> Ok (public, allowed, None)
      | [ public; allowed; psk ] -> Ok (public, allowed, Some psk)
      | _ -> Error (msgf "Invalid peer %S (expected PUBKEY:CIDR,...[:PSK])" str) in
    let* public = decode_key public in
    let* allowed = prefixes allowed in
    let* psk = match psk with
      | Some psk -> Result.map Option.some (decode_key psk)
      | None -> Ok None in
    let public = Zostera.public_of_octets public in
    let psk = Option.map Zostera.psk psk in
    Ok { public; psk; allowed } in
  let pp ppf { public; allowed; _ } =
    Fmt.pf ppf "%s:%a"
      (Base64.encode_string (Zostera.octets_of_public public))
      Fmt.(list ~sep:(any ",") Ipaddr.V4.Prefix.pp) allowed in
  Arg.conv (parser, pp)

let peers =
  let doc =
    "A peer allowed to talk with us: its public key, the sources it is allowed \
     to use into the tunnel (and the destinations routed to it) and an optional \
     pre-shared key. This option can be repeated."
  in
  let open Arg in
  value
  & opt_all peer []
  & info [ "peer" ] ~doc ~docs:docs_wireguard ~docv:"PUBKEY:CIDRV4,...[:PSK]"

let listen_port =
  let doc = "The UDP port on which we listen for our peers." in
  let open Arg in
  value
  & opt int 51820
  & info [ "listen-port" ] ~doc ~docs:docs_wireguard ~docv:"PORT"

let setup secret peers port mtu =
  let ( let* ) = Result.bind in
  let* identity = Zostera.of_octets secret
    |> Result.map_error (fun err -> msgf "%a" Zostera.pp_error err) in
  let* () =
    if mtu >= 68 && mtu <= 0xffff then Ok ()
    else Error (`Msg "The MTU of the tunnel must be between 68 and 65535") in
  let keys = List.map (fun peer -> Zostera.octets_of_public peer.public) peers in
  let* () =
    if List.length (List.sort_uniq String.compare keys) = List.length keys
    then Ok () else Error (`Msg "A peer is declared several times") in
  Ok { identity; peers; port; mtu }

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

let mtu =
  let doc = "The MTU of the tunnel (TCP MSS are clamped according to it)." in
  let open Arg in
  value
  & opt int 1420
  & info [ "mtu" ] ~doc ~docs:docs_wireguard ~docv:"MTU"

let setup =
  let open Term in
  const setup $ private_key $ peers $ listen_port $ mtu
  |> term_result ~usage:false
