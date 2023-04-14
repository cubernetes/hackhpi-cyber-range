#!/usr/bin/env bash

domain=hackhpi23.timo.one

if [ -n "${1}" ]; then
  domain="${1}"
fi

curl -sL https://${domain}/api/red -X POST -H "Content-Type: application/json" -d "{\"data\": \"start of attack\", \"timestamp\": \"$(date +%s)\"}"

sleep .5

curl -sL https://${domain}/api/red -X POST -H "Content-Type: application/json" -d "{\"data\": \"nmap scanning\", \"timestamp\": \"$(date +%s)\"}"

sleep 1

curl -L https://${domain}/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"<b style='color: yellow'>IDS: Malicious Activity was detected</b>\", \"timestamp\": \"$(date +%s)\"}"

sleep .5

curl -L https://${domain}/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"<b style='color: red'>Malicious IP: 141.89.221.182</b>\", \"timestamp\": \"$(date +%s)\"}"

sleep .5

curl -sL https://${domain}/api/red -X POST -H "Content-Type: application/json" -d "{\"data\": \"ssh bruteforce\", \"timestamp\": \"$(date +%s)\"}"

sleep 2

curl -sL https://${domain}/api/red -X POST -H "Content-Type: application/json" -d "{\"data\": \"lateral scanning\", \"timestamp\": \"$(date +%s)\"}"

sleep 3

curl -sL https://${domain}/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"ubuntu@192.168.0.17: ssh -p1337 -A -L80:localhost:8080 mainframe3.localdomain\", \"timestamp\": \"$(( $(date +%s) + 360 ))\"}"
