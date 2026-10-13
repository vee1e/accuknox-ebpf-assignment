#!/usr/bin/env bash
# Scripted terminal demo for the recording (Problem 1 + Problem 2).
# Run on Linux as root:  sudo bash ./demo.sh
set -euo pipefail

cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "demo: must run as root"; exit 1; }
[ "$(uname -s)" = "Linux" ] || { echo "demo: Linux only"; exit 1; }

echo "=== building ==="
go build -o /tmp/ak-p1 ./cmd/p1
go build -o /tmp/ak-p2 ./cmd/p2
go build -o /tmp/ak-dialer ./testdata/dialer

cleanup() {
  echo "--- cleaning up ---"
  kill "$S4040" "$S4050" 2>/dev/null || true
  kill "$P1" "$P2" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "=== starting test servers on 4040 and 4050 ==="
/tmp/ak-dialer --serve --port 4040 >/tmp/srv4040.log 2>&1 & S4040=$!
/tmp/ak-dialer --serve --port 4050 >/tmp/srv4050.log 2>&1 & S4050=$!
sleep 1

echo
echo "############ Problem 1: drop TCP dport 4040 ############"
/tmp/ak-p1 --port 4040 --iface lo --stats 0 >/tmp/p1.log 2>&1 & P1=$!
sleep 1
echo "--- dial 4040 (expect FAIL) ---"
/tmp/ak-dialer --comm demodial --port 4040 || true
echo "--- dial 4050 (expect OK) ---"
/tmp/ak-dialer --comm demodial --port 4050
echo "--- p1 log ---"; cat /tmp/p1.log
kill "$P1"; wait "$P1" 2>/dev/null || true; P1=""

echo
echo "--- restart p1 with --port 4050: block moves immediately ---"
/tmp/ak-p1 --port 4050 --iface lo --stats 0 >/tmp/p1b.log 2>&1 & P1=$!
sleep 1
echo "--- dial 4040 (expect OK now) ---"
/tmp/ak-dialer --comm demodial --port 4040
echo "--- dial 4050 (expect FAIL now) ---"
/tmp/ak-dialer --comm demodial --port 4050 || true
kill "$P1"; wait "$P1" 2>/dev/null || true; P1=""
echo "--- traffic restored after detach ---"
/tmp/ak-dialer --comm demodial --port 4040
/tmp/ak-dialer --comm demodial --port 4050

echo
echo "############ Problem 2: myprocess only on 4040 ############"
/tmp/ak-p2 --process myprocess --port 4040 >/tmp/p2.log 2>&1 & P2=$!
sleep 1
echo "--- myprocess -> 4040 (expect OK) ---"
/tmp/ak-dialer --comm myprocess --port 4040
echo "--- myprocess -> 4050 (expect FAIL) ---"
/tmp/ak-dialer --comm myprocess --port 4050 || true
echo "--- otherproc -> 4050 (expect OK, unaffected) ---"
/tmp/ak-dialer --comm otherproc --port 4050
echo "--- stopping demo servers so bind tests own the ports ---"
kill "$S4040" "$S4050" 2>/dev/null || true
sleep 1
echo "--- myprocess binds 4040 (expect OK) ---"
/tmp/ak-dialer --comm myprocess --port 4040 --bind
FREE_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])' 2>/dev/null || echo 4051)
echo "--- myprocess binds $FREE_PORT (expect FAIL, denied) ---"
/tmp/ak-dialer --comm myprocess --port "$FREE_PORT" --bind || true
echo "--- otherproc binds $FREE_PORT (expect OK, unaffected) ---"
/tmp/ak-dialer --comm otherproc --port "$FREE_PORT" --bind
echo "--- p2 log ---"; cat /tmp/p2.log
kill "$P2"; wait "$P2" 2>/dev/null || true; P2=""

echo
echo "=== demo complete: detach restored all traffic ==="
