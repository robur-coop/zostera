(* NOTE(dinosaure): see [ratelimiter.go] *)

type entry = { mutable tokens : float; mutable last : int }
type t = { tbl: (string, entry) Hashtbl.t; mutable gc : int }

let _GC_INTERVAL = 1_000_000_000 (* 1s *)
let _ENTRY_TTL = 1_000_000_000 (* 1s *)
let _PACKETS_PER_SECOND = 20.

(* NOTE(dinosaure): here, we accept a burst of 5 packets. *)

let _BURST = 5.
let _MAX_ENTRIES = 8192

let gc t ~now:ts =
  if ts - t.gc >= _GC_INTERVAL then begin
    t.gc <- ts;
    let fn k entry acc =
      if ts - entry.last > _ENTRY_TTL
      then k :: acc else acc in
    let stale = Hashtbl.fold fn t.tbl [] in
    List.iter (Hashtbl.remove t.tbl) stale
  end

let key = function
  | Ipaddr.V4 v4 -> Ipaddr.V4.to_octets v4
  | Ipaddr.V6 v6 -> String.sub (Ipaddr.V6.to_octets v6) 0 8

let allow t ~now { Addr.ipaddr; _ } =
  let ts = now () in
  gc t ~now:ts;
  let key = key ipaddr in
  match Hashtbl.find_opt t.tbl key with
  | Some entry ->
    let elapsed = float_of_int (ts - entry.last) /. 1e9 in
    let tokens = entry.tokens +. elapsed *. _PACKETS_PER_SECOND in
    let tokens = Float.min _BURST tokens in
    entry.tokens <- tokens;
    entry.last <- ts;
    if entry.tokens > 1.
    then begin entry.tokens <- entry.tokens -. 1.; true end
    else false
  | None when Hashtbl.length t.tbl >= _MAX_ENTRIES -> false
  | None ->
    Hashtbl.replace t.tbl key { tokens= _BURST -. 1.; last= ts };
    true

let create () = { tbl= Hashtbl.create 0x100; gc= 0 }
