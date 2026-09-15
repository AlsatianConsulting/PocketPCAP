#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
src="$repo_dir/app/src/test/resources/pcap-src"
out="$repo_dir/app/src/test/resources/analysis-fixture.pcapng"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

time_format='%Y-%m-%d %H:%M:%S.%f'
text2pcap -q -t "$time_format" -4 10.0.0.2,8.8.8.8 -u 53000,53 "$src/dns-queries.txt" "$work/dns-q.pcapng"
text2pcap -q -t "$time_format" -4 8.8.8.8,10.0.0.2 -u 53,53000 "$src/dns-success.txt" "$work/dns-ok.pcapng"
text2pcap -q -t "$time_format" -4 8.8.8.8,10.0.0.2 -u 53,53000 "$src/dns-nxdomain.txt" "$work/dns-nx.pcapng"
text2pcap -q -t "$time_format" -4 8.8.8.8,10.0.0.2 -u 53,53000 "$src/dns-servfail.txt" "$work/dns-sf.pcapng"
text2pcap -q -t "$time_format" -4 10.0.0.2,203.0.113.8 -T 51000,80 "$src/http-request.txt" "$work/http-q.pcapng"
text2pcap -q -t "$time_format" -4 203.0.113.8,10.0.0.2 -T 80,51000 "$src/http-response.txt" "$work/http-r.pcapng"
text2pcap -q -t "$time_format" -4 10.0.0.2,203.0.113.9 -T 52000,443 "$src/tls-client.txt" "$work/tls-q.pcapng"
text2pcap -q -t "$time_format" -4 203.0.113.9,10.0.0.2 -T 443,52000 "$src/tls-alert.txt" "$work/tls-r.pcapng"
text2pcap -q -t "$time_format" "$src/tcp-evidence.txt" "$work/tcp-evidence.pcapng"
mergecap -w "$out" "$work"/*.pcapng
tshark -r "$out" -q -z io,phs >/dev/null
mkdir -p "$work/objects"
tshark -r "$out" -q --export-objects "http,$work/objects"
test -s "$work/objects/health"
fields=(
  frame.number frame.time_epoch frame.time_relative frame.len frame.encap_type
  eth.src eth.dst wlan.sa wlan.da ip.src ip.dst ipv6.src ipv6.dst _ws.col.Protocol _ws.col.Info
  tcp.srcport tcp.dstport tcp.stream tcp.len tcp.flags.syn tcp.flags.ack tcp.flags.fin tcp.flags.reset
  tcp.analysis.retransmission tcp.analysis.fast_retransmission tcp.analysis.duplicate_ack
  tcp.analysis.out_of_order tcp.analysis.lost_segment tcp.analysis.ack_lost_segment tcp.analysis.zero_window
  udp.srcport udp.dstport udp.stream dns.id dns.flags.response dns.qry.name dns.qry.type dns.a dns.aaaa
  dns.flags.rcode dns.time http.request.method http.host http.request.uri http.response.code
  http.content_type http.content_length http.time http.request_in http.response_in
  tls.handshake.extensions_server_name tls.handshake.extensions_alpn_str tls.handshake.version tls.handshake.extensions.supported_version tls.record.version
  tls.handshake.ciphersuite tls.alert_message.desc tls.alert_message.level tls.handshake.type
  x509af.notBefore x509af.notAfter x509af.notBeforeTime x509af.notAfterTime x509sat.printableString x509sat.uTF8String
  _ws.malformed icmp.type.error icmpv6.type.error
)
field_args=()
for field in "${fields[@]}"; do field_args+=( -e "$field" ); done
tshark -r "$out" -n -T fields "${field_args[@]}" -E separator=/t -E occurrence=a -E 'aggregator=|' -E quote=n \
  | sed 's/[[:space:]]*$//' > "$repo_dir/app/src/test/resources/analysis-fixture.tsv"
echo "Generated $out"
