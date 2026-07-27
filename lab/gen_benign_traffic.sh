#!/usr/bin/env bash
# lab/gen_benign_traffic.sh
#
# Purpose: Generate varied benign HTTP traffic against lab/target_service.py
#          from the benign VM, for M4/M5 lab runs. Mixes repeated GETs,
#          searches, logins, and a few short-timeout probes to a closed port
#          (normal "flaky client" behavior) so the capture has many more
#          benign flow-shapes than a handful of identical curl calls.
#
# Usage:   ./gen_benign_traffic.sh [count] [target_host]
#          ./gen_benign_traffic.sh 2000 192.168.56.1

COUNT=${1:-1000}
TARGET=${2:-192.168.56.1}

for i in $(seq 1 "$COUNT"); do
  case $((RANDOM % 5)) in
    0) curl -s "http://$TARGET/" -o /dev/null ;;
    1) curl -s "http://$TARGET/search?q=query$i" -o /dev/null ;;
    2) curl -s -X POST "http://$TARGET/login" -d "username=user$i&password=pass$i" -o /dev/null ;;
    3) curl -s --max-time 1 "http://$TARGET:8081/" -o /dev/null 2>/dev/null ;;
    4) curl -s "http://$TARGET/" -o /dev/null ;;
  esac
  sleep 0.$((RANDOM % 5 + 1))
done

echo "Done: sent $COUNT benign requests to $TARGET"
