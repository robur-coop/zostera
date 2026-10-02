let ( let* ) = Result.bind

type t =
  { ethd : Ethernet.daemon
  ; arpd : ARPv4.daemon
  ; icmpd : ICMPv4.daemon
  ; ipv4 : IPv4.t
  ; mtu : int }

let handler icmpd ((hdr, _payload) as pkt) =
  match hdr.IPv4.protocol with
  | 1 -> ICMPv4.transfer icmpd pkt (* NOTE(dinosaure): we can ping! *)
  | _ -> ()

let device ~name ?gateway cidr =
  let fn net () =
    let mac = Macaddr.of_octets_exn (Mkernel.Net.mac net :> string) in
    let fn () =
      let* ethd, eth = Ethernet.create ~mtu:(Mkernel.Net.mtu net) mac net in
      let* arpd, arp = ARPv4.create ~ipaddr:(Ipaddr.V4.Prefix.address cidr) eth in
      let* ipv4 = IPv4.create eth arp ?gateway ~cidr () in
      let icmpd = ICMPv4.handler ipv4 in
      IPv4.set_handler ipv4 (handler icmpd);
      let handler pkt = match pkt.Ethernet.protocol with
        | Ethernet.ARPv4 -> ARPv4.transfer arp pkt
        | Ethernet.IPv4 -> IPv4.input ipv4 pkt
        | Ethernet.IPv6 -> () in
      Ethernet.set_handler eth handler;
      Ok { ethd; arpd; icmpd; ipv4; mtu= Ethernet.mtu eth } in
    match fn () with
    | Ok outer -> outer
    | Error `MTU_too_small -> Fmt.failwith "%s: MTU too small" name in
  let finally t =
    ICMPv4.kill t.icmpd;
    ARPv4.kill t.arpd;
    Ethernet.kill t.ethd in
  Mkernel.(map fn [ net name ]) |> Mkernel.finally finally
