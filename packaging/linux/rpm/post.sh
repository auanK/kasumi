ver=""
if [ -x /usr/bin/kasumi ]; then
  ver="$(/usr/bin/kasumi --version 2>/dev/null | awk '{print $NF}')"
fi
if [ "${1:-1}" -gt 1 ]; then
  echo "kasumi: upgraded to v${ver:-unknown} (profiles preserved)"
else
  echo "kasumi: installed v${ver:-unknown} (/usr/bin/kasumi)"
fi
