# Zostera, a WireGuard protocol implementation in pure OCaml

Zostera is an implementation of the [WireGuard][wireguard] protocol in OCaml,
as well as the implementation of two unikernels: one that can replace a `wg0`
interface, and the other that can act as a WireGuard client. The aim is to
provide sandboxed computer executable (using [Solo5][solo5]) that handle
cryptography exclusively outside user space and kernel space, as these run via
the hypervisor.

Our [robur.coop][robur.coop] cooperative develops and maintains all the
libraries related to (and used here for) cryptography, namely
[`mirage-crypto`][mirage-crypto] and [`digestif`][digestif], as well as the
network-related software components such as [`mnet`][mnet], and maintains the
Solo5 project.

As with all our cooperative's projects, the core of the protocol is independent
of any scheduler; there is then a derivative implementation using our
[Miou][miou] scheduler and [`mkernel`][mkernel] to provide unikernels.

[wireguard]: https://www.wireguard.com/
[solo5]: https://github.com/solo5/solo5
[robur.coop]: https://robur.coop/
[mirage-crypto]: https://github.com/mirage/mirage-crypto
[digestif]: https://github.com/mirage/digestif
[mnet]: https://github.com/robur-coop/mnet
[miou]: https://github.com/robur-coop/miou
[mkernel]: https://github.com/robur-coop/mkernel
