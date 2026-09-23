let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let guard ~err fn = if fn () then Ok () else Error err
let ( let* ) = Result.bind

type t = int32

let gen ?g () =
  let tmp = Mirage_crypto_rng.generate ?g 4 in
  String.get_int32_be tmp 0

let unsafe_of_int32 x = x

let receiver pkt =
  let* () = guard ~err:(msgf "Truncated WireGuard packet packet") @@ fun () ->
    String.length pkt >= 12 in
  let k = String.get_int32_le pkt 0 in
  match k with
  | 2l -> Ok (String.get_int32_le pkt 8)
  | _ -> Ok (String.get_int32_le pkt 4)
(* TODO(dinosaure): should we be exhaustive? *)
