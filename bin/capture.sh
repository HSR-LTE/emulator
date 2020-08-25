#! /bin/bash

set -e

ip netns exec CLIENT tcpdump -i client0 -s 96 -w /tmp/client.pcap &
CLIENT_TCPDUMP=$!
ip netns exec SERVER tcpdump -i server0 -s 96 -w /tmp/server.pcap &
SERVER_TCPDUMP=$!
ip netns exec ROUTER ./bin/router &
ROUTER_PID=$!
ip netns exec SERVER ./bin/server &
SERVER_PID=$!
sleep 0.3

ip netns exec CLIENT ./bin/client
wait $SERVER_PID
kill $ROUTER_PID
kill $CLIENT_TCPDUMP
kill $SERVER_TCPDUMP
wait $ROUTER_PID || true
wait $CLIENT_TCPDUMP
wait $SERVER_TCPDUMP

pcap2csv() {
  FILENAME=$1
  shift
  tshark -r $FILENAME.pcap -T fields -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e tcp.ack -e tcp.seq -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.reset -e tcp.options.mptcp.rawdataseqno -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.window_size -e tcp.len -e tcp.hdr_len -e tcp.analysis.lost_segment -e tcp.analysis.ack_rtt -e tcp.analysis.retransmission -e tcp.analysis.fast_retransmission -e tcp.analysis.spurious_retransmission -e tcp.analysis.bytes_in_flight -E header=y -E separator=, "$@" > $FILENAME.csv
}

pcap2csv /tmp/client -Y "ip.addr == 10.0.1.2 && ip.addr == 10.0.1.3"
pcap2csv /tmp/server -Y "ip.addr == 10.0.1.2 && ip.addr == 10.0.1.3"
