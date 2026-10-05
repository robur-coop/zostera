let ( let* ) = Result.bind
let src = Logs.Src.create "zostera.inner"

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr
module SBytes = Slice_bytes

type t =
  { ethd : Ethernet.daemon
  ; arpd : ARPv4.daemon
  ; eth : Ethernet.t
  ; arp : ARPv4.t
  ; cidr : Ipaddr.V4.Prefix.t }

let device ~name ~handler:fn cidr =
  let fn net () =
    let mac = Macaddr.of_octets_exn (Mkernel.Net.mac net :> string) in
    let connect () =
      let* ethd, eth = Ethernet.create ~mtu:(Mkernel.Net.mtu net) mac net in
      let* arpd, arp = ARPv4.create ~ipaddr:(Ipaddr.V4.Prefix.address cidr) eth in
      let handler pkt = match pkt.Ethernet.protocol with
        | Ethernet.ARPv4 -> ARPv4.transfer arp pkt
        | Ethernet.IPv4 ->
          let payload = pkt.Ethernet.payload in
          let plen = SBstr.length payload in
          if plen >= 20 then
            let len = SBstr.get_uint16_be payload 2 in
            if len >= 20 && len <= plen then begin
              let buf = Bytes.make ((len + 15) land (lnot 15)) '\000' in
              SBstr.blit_to_bytes payload ~src_off:0 buf ~dst_off:0 ~len;
              fn (SBytes.make buf ~off:0 ~len)
            end
        | Ethernet.IPv6 -> () in
      Ethernet.set_handler eth handler;
      Ok { ethd; arpd; eth; arp; cidr } in
    match connect () with
    | Ok inner -> inner
    | Error `MTU_too_small -> Fmt.failwith "%s: MTU too small" name in
  let finally t =
    ARPv4.kill t.arpd;
    Ethernet.kill t.ethd in
  Mkernel.(map fn [ net name ]) |> Mkernel.finally finally

let send inner dst slice =
  let mtu = Ethernet.mtu inner.eth in
  let df = SBytes.get_uint16_be slice 6 land 0x4000 <> 0 in
  if SBytes.length slice > mtu && df
  then Log.warn (fun m -> m "Packet too bug for %a (%d byte(s))" Ipaddr.V4.pp dst (SBytes.length slice))
  else
    let mac = match ARPv4.ask inner.arp dst with
      | Some mac -> Ok mac
      | None -> ARPv4.query inner.arp dst in
    match mac with
    | Ok mac ->
      let send { Slice.buf; off; len }=
        let fn bstr = Bstr.blit_from_bytes buf ~src_off:off bstr ~dst_off:0 ~len; len in
        Ethernet.write_directly_into inner.eth ~len ~dst:mac ~protocol:Ethernet.IPv4 fn in
      List.iter send (Nat.fragment slice ~mtu)
    | Error err ->
      Log.warn (fun m -> m "Impossible to reach %a: %a" Ipaddr.V4.pp dst ARPv4.pp_error err)

let deliver inner nat ~allowed ~now buf len =
  match Nat.decode (Bytes.unsafe_to_string buf) with
  | Error _ -> Log.debug (fun m -> m "Invalid packet from the tunnel")
  | Ok hdr when hdr.Nat.len > len -> Log.warn (fun m -> m "Dishonest packet size from the tunnel")
  | Ok hdr when not (allowed hdr.Nat.src) -> Log.warn (fun m -> m "Packet from %a is not allowed by the peer" Ipaddr.V4.pp hdr.Nat.src)
  | Ok hdr ->
    let send (dst, slice) =
      if Ipaddr.V4.Prefix.mem dst inner.cidr
      then send inner dst slice
      else Log.warn (fun m -> m "%a is not on the private network" Ipaddr.V4.pp dst) in
    let pkt = SBytes.make buf ~off:0 ~len:hdr.Nat.len in
    match Nat.inbound nat ~hdr ~now pkt with
    | Ok pkts -> List.iter send pkts
    | Error err ->
      Log.debug (fun m -> m "Drop a packet from %a: %a" Ipaddr.V4.pp hdr.Nat.src Nat.pp_error err)
