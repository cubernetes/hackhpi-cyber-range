#!/usr/bin/env bash

domain=hackhpi23.timo.one

curl -L https://${domain}/api/red -X POST -H "Content-Type: application/json" -d "{\"data\": \"Start of post-exploitation\", \"timestamp\": \"$(date +%s)\"}"

curl -L https://${domain}/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"<b style='color: yellow'>Snort: Intrusion Detected!</b>\", \"timestamp\": \"$(date +%s)\"}"
