(* NOTE(dinosaurte): note to myself, actually it's **not** possible to do a
   zero copy because [Bruit]/WireGuard has a queue of what we would like to
   send. So we can not ensure an uninterruptible execution path between what we
   receive from a private network and what we would like to encrypt and send.
   Even if it exists [Zostera.send_into], it's too complicate for us to use it.
   This reflexion is for [outbound]. Let's see later for [inbound].

   NOTE(dinosaure): [outbound] and [inbound] take a [bytes] because they set it
   in place to avoid a copy. Because of [adjust], we can play without copies to
   incoming packets and set [src]/[dst] according to what we track. It's a bit
   ugly but eh... we would like perform 9000. On the top layer (our unikernel),
   we do a copy because we manipulate [Bstr.t] but, in anyway, we do copies
   because:
   - as we said for [outbound], [Bruit] keeps a queue of what we would like to
     send and encrypt.
   - for [inbound], [Bruit] gives to us [string] in any way.

   NOTE(dinosaure): Our implementation currently does not use a scheduler. This
   means that the buffers we handle are returned to the tasks (Miou) that have
   exclusive access to them without interruption. This feature is important
   because it means that [nat.ml] does not transfer ownership of a [bytes] to
   another task, and two tasks cannot have read/write access to it _at the same
   time_.

   In this case, [nat.ml] consumes [bytes], modifies them and generates
   [Slice_bytes.t] that may refer to the given [bytes]: in other words, there
   are **no copies**! Only the execution path where fragments are received
   (necessarily) involves copying. *)

module SBytes = Slice_bytes

let _MIN_PORT = 1024
let _1s = 1_000_000_000
let _TCP = 6
let _TCP_TIMEOUT = 7200 * _1s
let _TCP_FIN_TIMEOUT = 120 * _1s
let _TCP_RST_TIMEOUT = 10 * _1s
let _UDP = 17
let _UDP_TIMEOUT = 120 * _1s
let _ICMP = 1
let _ICMP_TIMEOUT = 30 * _1s
let _FRAG_TIMEOUT = 30 * _1s

let timeout_of_proto proto =
  if proto = _TCP then _TCP_TIMEOUT
  else if proto = _UDP then _UDP_TIMEOUT
  else _ICMP_TIMEOUT

let err_invalid_ipv4_packet = Error `Invalid_IPv4_packet
let err_ttl_exceeded = Error `TTL_exceeded
let err_all_ports_used = `All_ports_used
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let ( let* ) = Result.bind
let guard ~err fn = if fn () then Ok () else Error err

type error =
  [ `Invalid_IPv4_packet
  | `TTL_exceeded
  | `All_ports_used
  | `Msg of string ]

let pp_error ppf = function
  | `Invalid_IPv4_packet -> Fmt.string ppf "Invalid IPv4 packet"
  | `TTL_exceeded -> Fmt.string ppf "TTL exceeded"
  | `All_ports_used -> Fmt.string ppf "All ports used"
  | `Msg msg -> Fmt.string ppf msg

type ipv4_hdr =
  { ihl : int
  ; len : int
  ; uid : int
  ; df : bool
  ; mf : bool
  ; foff : int (* in bytes *)
  ; proto : int
  ; src : Ipaddr.V4.t
  ; dst : Ipaddr.V4.t }

(* NOTE(dinosaure): please god, save me from this world! *)
let decode ?(off= 0) str =
  let len = String.length str - off in
  if len < 20 || String.get_uint8 str off lsr 4 <> 4
  then err_invalid_ipv4_packet
  else
    let ihl = (String.get_uint8 str off land 0x0f) * 4 in
    let len = String.get_uint16_be str (off + 2) in
    if ihl < 20 || len < ihl || len > String.length str - off
    then err_invalid_ipv4_packet
    else
      let uid = String.get_uint16_be str (off + 4) in
      let flags = String.get_uint16_be str (off + 6) in
      let df = flags land 0x4000 <> 0 in
      let mf = flags land 0x2000 <> 0 in
      let foff = (flags land 0x1fff) * 8 in
      let proto = String.get_uint8 str (off + 9) in
      let src = Ipaddr.V4.of_int32 (String.get_int32_be str (off + 12)) in
      let dst = Ipaddr.V4.of_int32 (String.get_int32_be str (off + 16)) in
      Ok { ihl; len; uid; df; mf; foff; proto; src; dst; }

let getipv4 slice off =
  Ipaddr.V4.of_int32 (SBytes.get_int32_be slice off)

(* RFC 1624: chk = ~(~chk + ~old + new) *)
let adjust csum ~old v =
  let sum = (lnot csum land 0xffff) + (lnot old land 0xffff) + v in
  let sum = (sum land 0xffff) + (sum lsr 16) in
  let sum = (sum land 0xffff) + (sum lsr 16) in
  lnot sum land 0xffff

let set16 slice off v ~csums =
  let old = SBytes.get_uint16_be slice off in
  SBytes.set_uint16_be slice off v;
  let fn (csum, is_udp) =
    let chk = SBytes.get_uint16_be slice csum in
    if not (is_udp && chk = 0) then begin
      let chk = adjust chk ~old v in
      SBytes.set_uint16_be slice csum
        (if is_udp && chk = 0 then 0xffff else chk)
    end in
  List.iter fn csums

let setipv4 slice off ipaddr ~csums =
  let v = Ipaddr.V4.to_int32 ipaddr in
  let v = Int32.to_int v land 0xffffffff in
  set16 slice off (v lsr 16) ~csums;
  set16 slice (off + 2) (v land 0xffff) ~csums

let decr slice =
  let ttl = SBytes.get_uint8 slice 8 in
  if ttl <= 1 then false (* You die! *)
  else begin
    let w = SBytes.get_uint16_be slice 8 in
    set16 slice 8 (w - 0x100) ~csums:[ (10, false) ];
    true
  end

type key = { kproto : int; inside : Ipaddr.V4.t; iport : int; remote : Ipaddr.V4.t; rport : int }
type rkey = { rproto : int; eport : int; from : Ipaddr.V4.t; fport : int }
type fkey = { fproto : int; fsrc : Ipaddr.V4.t; fuid : int }
type entry = { key : key; rkey : rkey; mutable seen : int; mutable timeout : int }
type frag = { birth : int; mutable inside : Ipaddr.V4.t option; mutable pending : string list; mutable size : int }

type t =
  { public : Ipaddr.V4.t
  ; outs : (key, entry) Hashtbl.t (* LAN -> tunnel *)
  ; ins : (rkey, entry) Hashtbl.t (* tunnel -> LAN *)
  ; frags : (fkey, frag) Hashtbl.t
  ; used : (int, int) Hashtbl.t (* (proto, eport) -> refcount *)
  ; mutable next : int }

let create public =
  { public
  ; outs= Hashtbl.create 0x100
  ; ins= Hashtbl.create 0x100
  ; used= Hashtbl.create 0x100
  ; frags= Hashtbl.create 0x10
  ; next= _MIN_PORT }

let size t = Hashtbl.length t.outs

(* NOTE(dinosaure): one [rkey] has only one association *)

let clean_up t entry =
  Hashtbl.remove t.outs entry.key;
  Hashtbl.remove t.ins entry.rkey;
  let kgc = (entry.rkey.rproto lsl 16) lor entry.rkey.eport in
  match Hashtbl.find_opt t.used kgc with
  | Some n when n > 1 -> Hashtbl.replace t.used kgc (n - 1)
  | Some _ -> Hashtbl.remove t.used kgc
  | None -> ()

let clean_up t ~now =
  let fn _ entry acc =
    if now - entry.seen > entry.timeout
    then entry :: acc
    else acc in
  let expired = Hashtbl.fold fn t.outs [] in
  List.iter (clean_up t) expired;
  let fn _ frag = if now - frag.birth > _FRAG_TIMEOUT then None else Some frag in
  Hashtbl.filter_map_inplace fn t.frags

let allocate t ~now key =
  let free eport =
    let rproto = key.kproto
    and from = key.remote
    and fport = key.rport in
    let rkey = { rproto; eport; from; fport } in
    not (Hashtbl.mem t.ins rkey) in
  let rec search eport tries =
    if tries = 0 then None
    else
      let eport = if eport > 0xffff then _MIN_PORT else eport in
      if free eport
      && let kgc = (key.kproto lsl 16) lor eport in
         not (Hashtbl.mem t.used kgc)
      then begin t.next <- eport + 1; Some eport end
      else search (succ eport) (pred tries) in
  (* NOTE(dinosaure): first, we try to use the same port. Then, we try
     remaining possibilities. We should optimize how we search a new free port.
     If we don't find a new one, we clean up our table and retry again. And if
     we don't find a new solution, we are doomed...*)
  let eport =
    if key.iport >= _MIN_PORT && free key.iport
    then Some key.iport
    else match search t.next (0x10000 - _MIN_PORT) with
      | Some _ as value -> value
      | None ->
        clean_up t ~now;
        search t.next (0x10000 - _MIN_PORT) in
  match eport with
  | None -> None
  | Some eport ->
    let rproto = key.kproto
    and from = key.remote
    and fport = key.rport in
    let rkey = { rproto; eport; from; fport } in
    let entry = { key; rkey; seen= now; timeout= timeout_of_proto key.kproto } in
    Hashtbl.replace t.outs key entry;
    Hashtbl.replace t.ins rkey entry;
    let kgc = (key.kproto lsl 16) lor eport in
    let n = Option.value ~default:0 (Hashtbl.find_opt t.used kgc) in
    Hashtbl.replace t.used kgc (succ n);
    Some entry

let track slice off entry =
  let flags = SBytes.get_uint8 slice (off + 13) in
  if flags land 0x04 <> 0
  then entry.timeout <- Int.min entry.timeout _TCP_RST_TIMEOUT
  else if flags land 0x01 <> 0 then entry.timeout <- Int.min entry.timeout _TCP_FIN_TIMEOUT
  else if flags land 0x12 = 0x02 then entry.timeout <- _TCP_TIMEOUT

(* NOTE(dinosaure): the tunnel has a smaller MTU than the private network,
   we rewrite the MSS option of SYN packets to avoid fragmentation. *)
let clamp slice ~off ~len ~mss =
  let doff = (SBytes.get_uint8 slice (off + 12) lsr 4) * 4 in
  let flags = SBytes.get_uint8 slice (off + 13) in
  if flags land 0x02 <> 0
  && doff > 20 && doff <= len then
    let rec go pos =
      if pos >= off + doff then ()
      else match SBytes.get_uint8 slice pos with
        | 0 -> ()
        | 1 -> go (succ pos)
        | 2 when pos + 4 <= off + doff && SBytes.get_uint8 slice (pos + 1) = 4 ->
          if SBytes.get_uint16_be slice (pos + 2) > mss
          then set16 slice (pos + 2) mss ~csums:[ (off + 16, false) ]
        | _ -> 
          if pos + 1 >= off + doff then ()
          else
            let olen = SBytes.get_uint8 slice (pos + 1) in
            if olen < 2 then () else go (pos + olen) in
    go (off + 20)

(* from our private network to Internet *)
let outbound t ~now ?mss ?hdr (buf : bytes) =
  let* hdr, slice = match hdr with
    | Some hdr ->
      (* NOTE(dinosaure): [decr] has a side-effect. *)
      let* len = if Bytes.length buf < hdr.len then error_msgf "Truncated IPv4 packet"
        else Ok hdr.len in
      let slice = SBytes.make ~off:0 ~len buf in
      if not (decr slice) then err_ttl_exceeded
      else Ok (hdr, slice)
    | None ->
      let* hdr = decode (Bytes.unsafe_to_string buf) in
      let* len = if Bytes.length buf < hdr.len then error_msgf "Truncated IPv4 packet"
        else Ok hdr.len in
      let slice = SBytes.make ~off:0 ~len buf in
      if not (decr slice) then err_ttl_exceeded
      else Ok (hdr, slice) in
  match hdr with
  | { foff; _ } when foff > 0 ->
    (* NOTE(dinosaure): a non-first fragment, it does not carry TCP/UDP ports. *)
    setipv4 slice 12 t.public ~csums:[ (10, false) ];
    Ok hdr.len
  | hdr ->
    let off = hdr.ihl and len = hdr.len - hdr.ihl in
    let* key =
      if hdr.proto = _TCP && len >= 20
      || hdr.proto = _UDP && len >= 8
      then
        let kproto = hdr.proto
        and inside = hdr.src and iport = SBytes.get_uint16_be slice off
        and remote = hdr.dst and rport = SBytes.get_uint16_be slice (off + 2) in
        Ok { kproto; inside; iport; remote; rport }
      else if hdr.proto = _ICMP && len >= 8 && SBytes.get_uint8 slice off = 8
      then
        (* echo request, we use its identifier as a port *)
        let kproto = hdr.proto
        and inside = hdr.src and iport = SBytes.get_uint16_be slice (off + 4)
        and remote = hdr.dst and rport = 0 in
        Ok { kproto; inside; iport; remote; rport }
      else error_msgf "Unsupported protocol %d" hdr.proto in
    let* entry = match Hashtbl.find_opt t.outs key with
      | Some entry -> Ok entry
      | None -> allocate t ~now key |> Option.to_result ~none:err_all_ports_used in
    entry.seen <- now;
    let eport = entry.rkey.eport in
    if hdr.proto = _ICMP then begin
      setipv4 slice 12 t.public ~csums:[ (10, false) ];
      set16 slice (off + 4) eport ~csums:[ (off + 2, false) ]
    end else begin
      let l4 =
        if hdr.proto = _TCP
        then (off + 16, false)
        else (off + 6, true) in
      setipv4 slice 12 t.public ~csums:[ (10, false); l4 ];
      set16 slice off eport ~csums:[ l4 ];
      if hdr.proto = _TCP then begin
        track slice off entry;
        let fn mss = clamp slice ~off ~len ~mss in
        Option.iter fn mss
      end
    end;
    Ok hdr.len

let fragment slice ~mtu =
  let ihl = (SBytes.get_uint8 slice 0 land 0x0f) * 4 in
  let len = SBytes.get_uint16_be slice 2 in
  if len <= mtu then [ slice ]
  else if mtu < ihl + 8 then invalid_arg "MTU too small"
  else
    let flags = SBytes.get_uint16_be slice 6 in
    let mf = flags land 0x2000 <> 0 and foff = (flags land 0x1fff) * 8 in
    let payload = len - ihl in
    let rec go pos acc =
      if pos >= payload then List.rev acc
      else
        let hlen = if pos = 0 then ihl else 20 in
        let size = Int.min ((mtu - hlen) land (lnot 7)) (payload - pos) in
        let last = pos + size = payload in
        let frag = Bytes.create (hlen + size) in
        SBytes.blit_to_bytes slice ~src_off:0 frag ~dst_off:0 ~len:hlen; (* copy IPv4 header *)
        Bytes.set_uint8 frag 0 (0x40 lor (hlen / 4)); (* set IHL *)
        SBytes.blit_to_bytes slice ~src_off:(ihl + pos) frag ~dst_off:hlen ~len:size; (* copy IPv4 payload *)
        Bytes.set_uint16_be frag 2 (hlen + size); (* set total-length *)
        let mf = if last then mf else true in
        Bytes.set_uint16_be frag 6 ((if mf then 0x2000 else 0) lor ((foff + pos) / 8)); (* set fragment offset *)
        Bytes.set_uint16_be frag 10 0; (* set checksum to 0 *)
        Bytes.set_uint16_be frag 10
          (Utcp.Checksum.digest_string (Bytes.unsafe_to_string frag) ~off:0 ~len:hlen);
        (* set checksum, TODO(dinosaure): may be copy/paste and let OCaml
           to optimize such call (because we don't have cross-module optimisations). *)
        go (pos + size) (SBytes.make frag :: acc) in
    go 0 []

let error t ~now hdr slice =
  let off = hdr.ihl in
  let inner = off + 8 in
  if hdr.len - inner < 28 then error_msgf "Truncated ICMP error"
  else
    (* NOTE(dinosaure): let's try to introspect the ICMP error and the IPv4
       packet inside it (if it corresponds to a tracked connection). *)
    let iihl = (SBytes.get_uint8 slice inner land 0x0f) * 4 in
    let proto = SBytes.get_uint8 slice (inner + 9) in
    let src = getipv4 slice (inner + 12)
    and dst = getipv4 slice (inner + 16) in
    let ifoff = SBytes.get_uint16_be slice (inner + 6) land 0x1fff in
    if iihl < 20 || hdr.len - inner < iihl + 8 || ifoff <> 0
    || not (Ipaddr.V4.compare src t.public = 0)
    then error_msgf "Unexpected ICMP error"
    else
      let l4 = inner + iihl in
      let rkey =
        if proto = _TCP || proto = _UDP
        then
          let rproto = proto
          and eport = SBytes.get_uint16_be slice l4
          and from = dst
          and fport = SBytes.get_uint16_be slice (l4 + 2) in
          Some { rproto; eport; from; fport }
        else if proto = _ICMP && SBytes.get_uint8 slice l4 = 8
        then
          let rproto = proto
          and eport = SBytes.get_uint16_be slice (l4 + 4)
          and from = dst
          and fport = 0 in
          Some { rproto; eport; from; fport }
        else None in
      match Option.bind rkey (Hashtbl.find_opt t.ins) with
      | None -> error_msgf "ICMP error without mapping"
      | Some entry ->
        entry.seen <- now;
        setipv4 slice 16 entry.key.inside ~csums:[ (10, false) ];
        setipv4 slice (inner + 12) entry.key.inside ~csums:[ (inner + 10, false) ];
        if proto = _ICMP
        then SBytes.set_uint16_be slice (l4 + 4) entry.key.iport
        else SBytes.set_uint16_be slice l4 entry.key.iport;
        (* NOTE(dinosaure): we don't compute the checksum of the inner packet. *)
        SBytes.set_uint16_be slice (off + 2) 0; (* ICMP checksum *)
        let { Slice.buf; off= abs; _ } = slice in
        let len = hdr.len - off
        and abs_off = abs + off
        and str = Bytes.unsafe_to_string buf in
        let chk = Utcp.Checksum.digest_string ~off:abs_off ~len str in
        SBytes.set_uint16_be slice (off + 2) chk;
        Ok entry.key.inside

let translate t ~now hdr slice =
  let off = hdr.ihl and len = hdr.len - hdr.ihl in
  if hdr.proto = _ICMP && len >= 8 then
    match SBytes.get_uint8 slice off with
    | 0 ->
      let rproto = _ICMP
      and eport = SBytes.get_uint16_be slice (off + 4)
      and from = hdr.src
      and fport = 0 in
      let rkey = { rproto; eport; from; fport } in
      begin match Hashtbl.find_opt t.ins rkey with
      | None -> error_msgf "ICMP echo reply without mapping"
      | Some entry ->
        entry.seen <- now;
        setipv4 slice 16 entry.key.inside ~csums:[ (10, false) ];
        set16 slice (off + 4) entry.key.iport ~csums:[ (off + 2, false) ];
        Ok entry.key.inside end
    (* 3: Destination unreachable
       11: Time Exceeded
       12: Bad IP header *)
    | 3 | 11 | 12 -> error t ~now hdr slice
    | n -> error_msgf "Unsupported ICMP message %d" n
  else if hdr.proto = _TCP && len >= 20
       || hdr.proto = _UDP && len >= 8
  then
    let rproto = hdr.proto
    and eport = SBytes.get_uint16_be slice (off + 2) (* TCP/UPD port *)
    and from = hdr.src
    and fport = SBytes.get_uint16_be slice off in
    let rkey = { rproto; eport; from; fport } in
    begin match Hashtbl.find_opt t.ins rkey with
    | None -> error_msgf "No mapping for the given packet"
    | Some entry ->
      entry.seen <- now;
      let l4 = if hdr.proto = _TCP then (off + 16, false) else (off + 6, true) in
      setipv4 slice 16 entry.key.inside ~csums:[ (10, false); l4 ];
      set16 slice (off + 2) entry.key.iport ~csums:[ l4 ];
      if hdr.proto = _TCP
      then track slice off entry;
      Ok entry.key.inside end
  else error_msgf "Unsupported protocol %d" hdr.proto

let rewrite_dst inside slice =
  if decr slice then begin
    setipv4 slice 16 inside ~csums:[ (10, false) ];
    Some (inside, slice)
  end else None

let frag t ~now hdr slice =
  let fproto = hdr.proto
  and fsrc = hdr.src
  and fuid = hdr.uid in
  let fkey = { fproto; fsrc; fuid } in
  match translate t ~now hdr slice with
  | Error _ as err -> Hashtbl.remove t.frags fkey; err
  | Ok inside ->
    let pending = match Hashtbl.find_opt t.frags fkey with
      | Some frag -> List.rev frag.pending
      | None -> [] in
    let frag = { birth= now; inside= Some inside; pending= []; size= 0 } in
    Hashtbl.replace t.frags fkey frag;
    (* NOTE(dinosaure): ok, it's COMPLETELY unsafe but trust me here. *)
    let fn str = SBytes.make ~off:0 ~len:(String.length str) (Bytes.unsafe_of_string str) in
    let pending = List.map fn pending in
    let fn = rewrite_dst inside in
    Ok ((inside, slice) :: List.filter_map fn pending)

let _MAX_PENDING = 0x10_000
let _MAX_FRAGS = 1024

let next t ~now hdr slice =
  let fproto = hdr.proto
  and fsrc = hdr.src
  and fuid = hdr.uid in
  let fkey = { fproto; fsrc; fuid } in
  match Hashtbl.find_opt t.frags fkey with
  | Some { inside= Some inside; _ } ->
    Ok (Option.to_list (rewrite_dst inside slice))
  | Some frag when frag.size + hdr.len > _MAX_PENDING ->
    Hashtbl.remove t.frags fkey;
    error_msgf "Too many pending fragments"
  | Some frag ->
    (* NOTE(dinosaure): [Bytes.to_string] is REALLY important here! *)
    frag.pending <- SBytes.to_string slice :: frag.pending;
    frag.size <- frag.size + hdr.len;
    Ok []
  | None ->
    if Hashtbl.length t.frags >= _MAX_FRAGS then clean_up t ~now;
    if Hashtbl.length t.frags >= _MAX_FRAGS then error_msgf "Too many fragmented datagrams"
    else begin
      let pending = [ SBytes.to_string slice ] in
      let frag = { birth= now; inside= None; pending; size= hdr.len } in
      Hashtbl.replace t.frags fkey frag;
      Ok []
    end

(* from Internet to our private network *)
let inbound t ~now ?hdr slice =
  let* hdr = match hdr with
    | Some hdr -> Ok hdr
    | None ->
      let { Slice.buf; off; _ } = slice in
      decode ~off (Bytes.unsafe_to_string buf) in
  let* () = guard ~err:(msgf "Truncated IPv4 packet") @@ fun () ->
    SBytes.length slice >= hdr.len in
  let slice = SBytes.sub slice ~off:0 ~len:hdr.len in
  if not (Ipaddr.V4.compare hdr.dst t.public = 0)
  then error_msgf "Packet for %a" Ipaddr.V4.pp hdr.dst
  else
    if hdr.foff > 0 then next t ~now hdr slice
    (* NOTE(dinosaure): [decr] has a side effect on [buf]. Don't move it! *)
    else if not (decr slice) then err_ttl_exceeded
    else if hdr.mf then frag t ~now hdr slice
    else
      let* inside = translate t ~now hdr slice in
      Ok [ inside, slice ]
