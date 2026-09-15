type t = { ipaddr : Ipaddr.t; port : int }

let ( let* ) = Result.bind
let v ipaddr ~port = { ipaddr; port }

let of_string str ~port =
  let* ipaddr, port = Ipaddr.with_port_of_string ~default:port str in
  Ok { ipaddr; port }

let of_string_exn str ~port =
  match Ipaddr.with_port_of_string ~default:port str with
  | Ok (ipaddr, port) -> { ipaddr; port }
  | Error _ -> invalid_arg "Bruit.addr_of_string_exn"

let to_octets { ipaddr; port } =
  let buf = Bytes.create 2 in
  Bytes.set_uint16_be buf 0 port;
  let port = Bytes.unsafe_to_string buf in
  Ipaddr.to_octets ipaddr ^ port
