#!/usr/bin/env bash


curl -L https://hackhpi.kyudev.xyz/api/red -X POST -H "Content-Type: application/json" -d "{\"data\": \"Start of post-exploitation\", \"timestamp\": \"$(date +%s)\"}"
curl -L https://hackhpi.kyudev.xyz/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"\", \"timestamp\": \"$(date +%s)\"}"
