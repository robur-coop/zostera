(* ECN (RFC 3168) for tunnels, as wireguard-linux does with
   [include/net/inet_ecn.h] and [include/net/ip_tunnels.h]. *)

let _NOT_ECT = 0
let _ECT_1 = 1
let _ECT_0 = 2
let _CE = 3
let _MASK = 3

(* AF41, plus 00 ECN, see [drivers/net/wireguard/messages.h].

   NOTE(dinosaure): such flag tells to a TCP/IP stack to have a high insurance
   to be forwarded & a "low drop precedence". The goal is to ensure that
   [msg1]/[msg2] are really transmitted. *)
let _HANDSHAKE_DSCP = 0x88

let dsfield pkt =
  if String.length pkt > 1 then match String.get_uint8 pkt 0 lsr 4 with
    | 4 when String.length pkt >= 20 -> String.get_uint8 pkt 1
    | 6 when String.length pkt >= 40 -> (String.get_uint16_be pkt 0 lsr 4) land 0xff
    | _ -> 0
  else 0

(* NOTE(dinosaure): [INET_ECN_encapsulate]

   > The full-functionality option for ECN encapsulation is to copy the ECN
   > codepoint of the inside header to the outside header on encapsulation if
   > the inside header is not-ECT or ECT, and to set the ECN codepoint of the
   > outside header to ECT(0) if the ECN codepoint of the inside header is CE.

   Jason told me to copy it, I don't understand everything... *)
let encapsulate ~outer inner =
  let outer = outer land lnot _MASK in
  if inner land _MASK = _CE then outer lor _ECT_0
  else outer lor (inner land _MASK)

let encap pkt = encapsulate ~outer:0 (dsfield pkt)

let adjust csum ~old v =
  let sum = (lnot csum land 0xffff) + (lnot old land 0xffff) + v in
  let sum = (sum land 0xffff) + (sum lsr 16) in
  let sum = (sum land 0xffff) + (sum lsr 16) in
  lnot sum land 0xffff

let set_dsfield pkt ds =
  let buf = Bytes.of_string pkt in
  let old = Bytes.get_uint16_be buf 0 in
  begin match (String.length pkt >= 1 && String.get_uint8 pkt 0 lsr 4 = 4) with
  | true (* IPv4 *) ->
    let v = (old land 0xff00) lor ds in
    Bytes.set_uint16_be buf 0 v;
    let csum = adjust (Bytes.get_uint16_be buf 10) ~old v in
    Bytes.set_uint16_be buf 10 csum
  | _ (* IPv6? *) ->
    Bytes.set_uint16_be buf 0 ((old land 0xf00f) lor (ds lsl 4))
  end;
  Bytes.unsafe_to_string buf

let decap ~outer pkt =
  let inner = dsfield pkt in
  if inner land _MASK = _NOT_ECT then pkt
  else if outer land _MASK = _CE then
    (* [INET_ECN_set_ce] *)
    if inner land _MASK = _CE then pkt else set_dsfield pkt (inner lor _CE)
  else if outer land _MASK = _ECT_1 && inner land _MASK = _ECT_0 then
    (* [INET_ECN_set_ect1] *)
    set_dsfield pkt (inner lxor _MASK)
  else pkt
