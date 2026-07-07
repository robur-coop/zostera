type initiator
type responder
type 'a handshake

type error =
  [ `Msg of string | Mirage_crypto_ec.error ]

val pp_error : error Fmt.t

type psk

val psk : string -> psk

val run : unit -> (unit, [> error ]) result
