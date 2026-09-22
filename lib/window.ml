(* see [replay.go] *)

type t = { mutable last : int64; bits : bytes }

let _BLOCKS = 128
let _SIZE = Int64.of_int ((_BLOCKS - 1) * 64)

let make () = { last= 0L; bits= Bytes.make (_BLOCKS * 8) '\000' }
let get t idx = Bytes.get_int64_ne t.bits (idx * 8)
let set t idx value = Bytes.set_int64_ne t.bits (idx * 8) value
let index counter = Int64.to_int (Int64.logand counter (Int64.of_int (_BLOCKS - 1)))

let reset t =
  t.last <- 0L;
  Bytes.fill t.bits 0 (_BLOCKS * 8) '\000'

let reject_after_messages =
  let open Int64 in
  sub (neg (shift_left 1L 13)) 1L (* -8193 *)

let validate t ?(limit= reject_after_messages) counter =
  if Int64.unsigned_compare counter limit >= 0
  then false
  else
    let block = Int64.shift_right_logical counter 6 in
    let continue = if Int64.unsigned_compare counter t.last > 0 then begin
        let current = Int64.shift_right_logical t.last 6 (* blockBitLog *) in
        let diff = Int64.sub block current in
        let diff = if Int64.unsigned_compare diff (Int64.of_int _BLOCKS) > 0
          then _BLOCKS (* cap diff to clear the whole ring *)
          else Int64.to_int diff in
        for i = 1 to diff do
          set t (index (Int64.add current (Int64.of_int i))) 0L
        done;
        t.last <- counter; true
      end else Int64.unsigned_compare (Int64.sub t.last counter) _SIZE <= 0 in
    continue &&
    let idx = index block in
    let old = get t idx in
    let bit = Int64.shift_left 1L (Int64.to_int (Int64.logand counter 63L)) in
    let neu (* new *) = Int64.logor old bit in
    set t idx neu;
    old <> neu
