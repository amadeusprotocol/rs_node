# WireGuard setup

Following are configs to create a wireguard tunnel to get a public IP address for local
Amadeus node development, testing and hosting. Note the `PostUp` and `PostDown` rules, first
three are needed so that your laptop can access the internet through the VPN, second two
are needed to hole-punch the `<server-ip>:36969` UDP port into the local laptop.

Server config (`/etc/wireguard/wg0.conf`):

```bash
[Interface]
PrivateKey = <server-private-key>
Address = 10.0.0.1/24
ListenPort = 51820

# NAT for egress + allow WG forwarding
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# DNAT public:36969/udp -> 10.0.0.2:36969 and permit it
PostUp = iptables -t nat -A PREROUTING -i eth0 -p udp --dport 36969 -j DNAT --to-destination 10.0.0.2:36969
PostUp = iptables -A FORWARD -p udp -d 10.0.0.2 --dport 36969 -j ACCEPT

PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D PREROUTING -i eth0 -p udp --dport 36969 -j DNAT --to-destination 10.0.0.2:36969
PostDown = iptables -D FORWARD -p udp -d 10.0.0.2 --dport 36969 -j ACCEPT

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
```

Client config (`/etc/wireguard/server.conf`):

```bash
[Interface]
PrivateKey = <client-private-key>
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
AllowedIPs = 0.0.0.0/0
Endpoint = <server-ip>:51820
PersistentKeepalive = 25
```

To generate the wireguard keypair and to start/stop the server on both server/laptop, run:

```bash
wg genkey # will print the private key
echo "<private-key>"| wg pubkey # will print the public key
# don't forget to replace keys and server ip in configs above
sudo wg-quick up wg0
sudo wg-quick down wg0
```