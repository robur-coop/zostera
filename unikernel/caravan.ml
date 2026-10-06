external caravan : bytes -> bool = "caravan" [@@noalloc]

let private_key () =
  let buf = Bytes.create 32 in
  if caravan buf then Some (Bytes.unsafe_to_string buf) else None
