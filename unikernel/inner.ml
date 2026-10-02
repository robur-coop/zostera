let ( let* ) = Result.bind

type t =
  { ethd : Ethernet.daemon
  ; arpd : ARPv4.daemon
  ; eth : Ethernet.t
  ; arp : ARPv4.t
  ; cidr : Ipaddr.V4.Prefix.t }

let device ~name cidr =
  let fn net () =
    let mac = Macaddr.of_octets_exn (Mkernel.Net.mac net :> string) in
    let connect () =
      let* ethd, eth = Ethernet.create ~mtu:(Mkernel.Net.mtu net) mac net in
      let* arpd, arp = ARPv4.create ~ipaddr:(Ipaddr.V4.Prefix.address cidr) eth in
      let handler pkt = match pkt.Ethernet.protocol with
        | Ethernet.ARPv4 -> ARPv4.transfer arp pkt
        | Ethernet.IPv4 | Ethernet.IPv6 -> () in
      Ethernet.set_handler eth handler;
      Ok { ethd; arpd; eth; arp; cidr } in
    match connect () with
    | Ok inner -> inner
    | Error `MTU_too_small -> Fmt.failwith "%s: MTU too small" name in
  let finally t =
    ARPv4.kill t.arpd;
    Ethernet.kill t.ethd in
  Mkernel.(map fn [ net name ]) |> Mkernel.finally finally


