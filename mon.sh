#!/usr/bin/env bash

#Requires sudo, strace and GNU grep

echo "<START>"

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

  grep            \
  --line-buffered \
  -o '".*[^"]"'   |

  grep            \
  --line-buffered \
  -o '[^"]*[^"]'  |

while IFS="" read -r char; do
  printf '%b' "$char"
done

echo "<END>"
