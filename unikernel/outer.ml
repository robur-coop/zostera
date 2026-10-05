let ( let* ) = Result.bind
let src = Logs.Src.create "zostera.outer"

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

type t =
  { ethd : Ethernet.daemon
  ; arpd : ARPv4.daemon
  ; icmpd : ICMPv4.daemon
  ; ipv4 : IPv4.t
  ; mtu : int }

let udp ~port fn hdr = function
  | IPv4.Slice slice ->
    let len = SBstr.length slice in
    if len >= 8 then
      let src_port = SBstr.get_uint16_be slice 0 in
      let dst_port = SBstr.get_uint16_be slice 2 in
      let len0 = SBstr.get_uint16_be slice 4 in
      if dst_port = port && len0 >= 8 && len0 <= len
      then
        let from = { Zostera.Addr.ipaddr= Ipaddr.V4 hdr.IPv4.src; port= src_port } in
        let str = SBstr.sub_string slice ~off:8 ~len:(len0 - 8) in
        fn from hdr.IPv4.tos str
  | IPv4.String str ->
    let len = String.length str in
    if len >= 8 then
      let src_port = String.get_uint16_be str 0 in
      let dst_port = String.get_uint16_be str 2 in
      let len0 = String.get_uint16_be str 4 in
      if dst_port = port && len0 >= 8 && len0 <= len
      then
        let from = { Zostera.Addr.ipaddr= Ipaddr.V4 hdr.IPv4.src; port= src_port } in
        let str = String.sub str 8 (len0 - 8) in
        fn from hdr.IPv4.tos str

let handler icmpd ~port fn ((hdr, payload) as pkt) =
  match hdr.IPv4.protocol with
  | 1 -> ICMPv4.transfer icmpd pkt (* NOTE(dinosaure): we can ping! *)
  | 17 -> udp ~port fn hdr payload
  | _ -> ()

let device ~name ?gateway ~port ~handler:fn cidr =
  let fn net () =
    let mac = Macaddr.of_octets_exn (Mkernel.Net.mac net :> string) in
    let fn () =
      let* ethd, eth = Ethernet.create ~mtu:(Mkernel.Net.mtu net) mac net in
      let* arpd, arp = ARPv4.create ~ipaddr:(Ipaddr.V4.Prefix.address cidr) eth in
      let* ipv4 = IPv4.create eth arp ?gateway ~cidr () in
      let icmpd = ICMPv4.handler ipv4 in
      IPv4.set_handler ipv4 (handler icmpd ~port fn);
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

let pseudo_hdr ~src ~dst ~len =
  let src = Int32.to_int (Ipaddr.V4.to_int32 src) land 0xffffffff in
  let dst = Int32.to_int (Ipaddr.V4.to_int32 dst) land 0xffffffff in
  (src lsr 16) + (src land 0xffff) + (dst lsr 16) + (dst land 0xffff) + 17 + len

let write_on_bstr ~src ~dst ~src_port ~dst_port pkt bstr =
  let len = String.length pkt in
  Bstr.set_uint16_be bstr 0 src_port;
  Bstr.set_uint16_be bstr 2 dst_port;
  Bstr.set_uint16_be bstr 4 (len + 8);
  Bstr.set_uint16_be bstr 6 0;
  Bstr.blit_from_string pkt ~src_off:0 bstr ~dst_off:8 ~len;
  let chk = lnot (Utcp.Checksum.digest ~off:0 ~len:(len + 8) bstr) land 0xffff in
  let chk = pseudo_hdr ~src ~dst ~len:(len + 8) + chk in
  let chk = (chk land 0xffff) + (chk lsr 16) in
  let chk = (chk land 0xffff) + (chk lsr 16) in
  let chk = lnot chk land 0xffff in
  Bstr.set_uint16_be bstr 6 (if chk = 0 then 0xffff else chk)

let to_string ~src ~dst ~src_port ~dst_port pkt =
  let len = String.length pkt in
  let buf = Bytes.create (len + 8) in
  Bytes.set_uint16_be buf 0 src_port;
  Bytes.set_uint16_be buf 2 dst_port;
  Bytes.set_uint16_be buf 4 (len + 8);
  Bytes.set_uint16_be buf 6 0;
  Bytes.blit_string pkt 0 buf 8 len;
  let chk = lnot (Utcp.Checksum.digest_string ~off:0 ~len:(len + 8) (Bytes.unsafe_to_string buf)) land 0xffff in
  let chk = pseudo_hdr ~src ~dst ~len:(len + 8) + chk in
  let chk = (chk land 0xffff) + (chk lsr 16) in
  let chk = (chk land 0xffff) + (chk lsr 16) in
  let chk = lnot chk land 0xffff in
  Bytes.set_uint16_be buf 6 (if chk = 0 then 0xffff else chk);
  Bytes.unsafe_to_string buf

let send outer ~src_port (dst : Zostera.Addr.t) ~ds pkt =
  match dst.ipaddr with
  | Ipaddr.V6 _ ->
    Log.warn (fun m -> m "IPv6 endpoints are not supported (%a)" Ipaddr.pp dst.ipaddr)
  | Ipaddr.V4 ipv4 ->
    let src = IPv4.src outer.ipv4 ~dst:ipv4 in
    let len = 8 + String.length pkt in
    let fn = write_on_bstr ~src ~dst:ipv4 ~src_port ~dst_port:dst.port pkt in
    let w =
      if 20 + len <= outer.mtu then IPv4.Writer.into outer.ipv4 ~len fn
      else
        let str = to_string ~src ~dst:ipv4 ~src_port ~dst_port:dst.port pkt in
        IPv4.Writer.of_string outer.ipv4 str in
    match IPv4.write outer.ipv4 ~tos:ds ~src ipv4 ~protocol:17 w with
    | Ok () -> ()
    | Error `Route_not_found ->
      Log.warn (fun m -> m "No route to %a" Ipaddr.V4.pp ipv4)
