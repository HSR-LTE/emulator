#! /bin/bash
set -e

if [ "x$1" = "x-f" ]; then
  ip netns del SERVER || true
  ip netns del CLIENT || true
  ip netns del ROUTER || true
fi

ip netns add SERVER
ip netns add CLIENT
ip netns add ROUTER

ip link add client0 type veth peer name client1
ip link add server0 type veth peer name server1

ip link set client0 netns CLIENT
ip link set server0 netns SERVER
ip link set client1 netns ROUTER
ip link set server1 netns ROUTER

ip netns exec ROUTER ip addr add 10.0.1.1 dev server1
ip netns exec ROUTER ip addr add 10.0.1.1 dev client1
ip netns exec SERVER ip addr add 10.0.1.2 dev server0
ip netns exec CLIENT ip addr add 10.0.1.3 dev client0

ip netns exec ROUTER ip link set server1 up
ip netns exec ROUTER ip link set client1 up
ip netns exec SERVER ip link set server0 up
ip netns exec CLIENT ip link set client0 up

ip netns exec ROUTER route add -host 10.0.1.2 dev server1
ip netns exec ROUTER route add -host 10.0.1.3 dev client1
ip netns exec SERVER route add -host 10.0.1.1 dev server0
ip netns exec SERVER route add -net 10.0.1.0/24 gw 10.0.1.1 dev server0
ip netns exec CLIENT route add -host 10.0.1.1 dev client0
ip netns exec CLIENT route add -net 10.0.1.0/24 gw 10.0.1.1 dev client0

ip netns exec CLIENT ethtool -K client0 tx-checksumming off
ip netns exec SERVER ethtool -K server0 tx-checksumming off

echo bbr | ip netns exec SERVER tee /proc/sys/net/ipv4/tcp_congestion_control
