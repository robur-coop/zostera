# WireGuard unikernels (client & server)

Here we present two unikernels that implement the WireGuard protocol. One
(`wg`) is intended for use as a client (so that your computer can connect to a
WireGuard server), whilst the other (`wgd`) is used as a server and can accept
multiple clients. It should be noted that the client performs NAT (Network
Address Translation), whereas the server does not (as WireGuard).

## Interfaces

Both unikernels require three interfaces:
- a so-called _public_/`service` interface
- a so-called _private_ interface
- an interface for collecting metrics (to monitor the unikernels)

You can create a file called `/etc/network/interfaces.d/albatross` containing
the following, and bring up the interfaces using `ifup` (Debian). This is
generally all that is required to deploy any unikernel using
[`albatross`][albatross] (you can, for example, follow our tutorial available
[here][albatross-tutorial]).

```
auto service
iface service inet static
  address 10.0.0.1/24
  bridge_ports none
  bridge_stp off
  bridge_fd 0

auto private
iface private inet static
  address 10.1.0.1/24
  bridge_ports none
  bridge_stp off
  bridge_fd 0
  post-up ip route add 192.168.2.0/24 via 10.1.0.2

auto metrics
iface metrics inet static
  address 192.168.0.1/24
  bridge_ports none
  bridge_stp off
  bridge_fd 0
```

If these interfaces do not exist, simply run this command to create them. We
then recommend installing `albatross` so that you have a (remotely accessible)
service capable of launching unikernels.

```shell
$ sudo ifup service private metrics
```

## Materials

WireGuard requires very little in the way of hardware: a private key on the
server side and a private key on the client side. These keys can easily be
generated using [`wg(8)`](https://www.man7.org/linux/man-pages/man8/wg.8.html).

```shell
$ umask 077
$ wg genkey | tee wgd.key | wg pubkey > wgd.pub
$ wg genkey | tee wg.key | wg pubkey > wg.pub
$ wg genpsk > psk
```

### Wgd

Next comes the network configuration. To do this, here is a description of the
network on your server.

```
brigde service 10.0.0.1/24
   wgd         10.0.0.2
bridge private 10.1.0.1/24
   wgd         10.1.0.2
bridge metrics 192.168.0.1/24
   wgd         192.168.0.2
tunnel         192.168.2.0/24
   peer0       192.168.2.2
   peer1       192.168.2.3
   peerX       192.168.2.x
```

We need to configure the server to enable IP forwarding, redirect WireGuard
packets to our unikernel and enable "MASQUERADE" on outgoing packets (you need
to replace `<public>` with your public interface - such as `eth0`, for example).

```shell
$ sudo sysctl -w net.ipv4.ip_forward=1
$ sudo iptables -t nat -A PREROUTING -i <public> -p udp --dport 51820 -j DNAT \
  --to-destination 10.0.0.2:51820
$ sudo iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o <public> -j MASQUERADE
```

We also need to configure the firewall to allow incoming and outgoing packets.

```shell
$ sudo ufw route allow \
  in on <public> out on service to 10.0.0.2 port 51820 proto udp
$ sudo ufw route allow \
  in on private out on <public>
```

If you have set up [`albatross`][albatross] (again, you can refer to our
[tutorial][albatross-tutorial]), you can now start your unikernel as follows:

```shell
$ albatross-client create --destination <public-IP> wgd wgd.hvt \
    --net service --net private --net metrics \
    --mem 64 --force --restart-on-fail \
    --arg="--ipv4=10.0.0.2/24" --arg="--ipv4-gateway=10.0.0.1" \
    --arg="--private-ipv4=10.1.0.2/24" --arg="--private-ipv4-gateway=10.1.0.1" \
    --arg="--metrics-ipv4=192.168.0.2/24" \
    --arg="--private-key=$(cat wgd.key)" \
    --arg="--peer=$(cat wg.pub):192.168.2.2/32:$(cat psk)"
```

It allows a peer to connect to the server and assigns it the address
`192.168.2.2`. The client can connect to the server using this WireGuard
configuration file `/etc/wireguard/wg0.conf`:

```init
[Interface]
PrivateKey = <wg.key>
Address = 192.168.2.2/32
MTU = 1420

[Peer]
PublicKey = <wgd.pub>
PresharedKey = <psk>
Endpoint = <public-IP>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

As a WireGuard client/server, simply initiate the tunnel with:
```shell
$ sudo wg-quick up wg0
$ sudo wg show
$ curl -4 ifconfig.me
$ sudo wg-quick down wg0
```

[albatross]: https://github.com/robur-coop/albatross
[albatross-tutorial]: https://uniker.nl/albatross/
