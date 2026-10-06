let magic = "zostera:key-slot"
let _STATE = String.length magic
let _KEY = _STATE + 4
let _KEY_LEN = 32
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( let* ) = Result.bind

let find str sub =
  let len = String.length sub in
  let rec go acc pos =
    match String.index_from_opt str pos sub.[0] with
    | None -> List.rev acc
    | Some pos when pos + len > String.length str -> List.rev acc
    | Some pos ->
      let acc = if String.sub str pos len = sub then pos :: acc else acc in
      go acc (pos + 1) in
  go [] 0

let read_key filename =
  let str = In_channel.with_open_bin filename In_channel.input_all in
  match Base64.decode (String.trim str) with
  | Ok key when String.length key = _KEY_LEN -> Ok key
  | Ok _ -> error_msgf "%s: a WireGuard key must be %d bytes" filename _KEY_LEN
  | Error (`Msg msg) -> error_msgf "%s: invalid key (%s)" filename msg

let run force key image output =
  let* key = read_key key in
  let str = In_channel.with_open_bin image In_channel.input_all in
  let* off = match find str magic with
    | [ off ] -> Ok off
    | [] -> error_msgf "%s: no key slot found (is it a wg/wgd image?)" image
    | _ -> error_msgf "%s: several key slots found" image in
  let* () =
    if off + _KEY + _KEY_LEN > String.length str
    then error_msgf "%s: truncated key slot" image
    else Ok () in
  let* () = match String.sub str (off + _STATE) 4 with
    | "NONE" -> Ok ()
    | "KEY!" when force -> Ok ()
    | "KEY!" -> error_msgf "%s: a key is already embedded (use --force)" image
    | _ -> error_msgf "%s: invalid key slot" image in
  let buf = Bytes.of_string str in
  Bytes.blit_string "KEY!" 0 buf (off + _STATE) 4;
  Bytes.blit_string key 0 buf (off + _KEY) _KEY_LEN;
  (* NOTE(dinosaure): the image now contains a secret, only its owner can
     read it (we keep the executable bit of the owner if any). *)
  let perm = if (Unix.stat image).Unix.st_perm land 0o100 <> 0 then 0o700 else 0o600 in
  let flags = [ Open_wronly; Open_creat; Open_trunc; Open_binary ] in
  let fn oc = Out_channel.output_bytes oc buf in
  Out_channel.with_open_gen flags perm output fn;
  Unix.chmod output perm;
  Fmt.pr "%s: key embedded at offset 0x%x, written into %s\n%!" image off output;
  Ok ()

open Cmdliner

let force =
  let doc = "Replace a key already embedded into the image." in
  Arg.(value & flag & info [ "f"; "force" ] ~doc)

let key =
  let doc = "The file which contains the private key (as $(b,wg genkey) generates)." in
  Arg.(required & opt (some file) None & info [ "k"; "key" ] ~doc ~docv:"FILE")

let image =
  let doc = "The unikernel image ($(b,wg) or $(b,wgd))." in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"IMAGE")

let output =
  let doc = "The new image (only readable by its owner)." in
  Arg.(required & opt (some string) None & info [ "o"; "output" ] ~doc ~docv:"FILE")

let cmd =
  let doc = "Embed a WireGuard private key into an unikernel image." in
  let info = Cmd.info "caravan" ~doc in
  Cmd.v info Term.(term_result ~usage:false (const run $ force $ key $ image $ output))

let () = Cmd.(exit @@ eval cmd)
