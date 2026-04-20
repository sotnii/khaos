ip -o link show \
| awk -F': ' '{split($2,a,"@"); print a[1]}' \
| grep '^pkst-' \
| while read iface; do
  echo "deleting $iface"
  ip link delete "$iface"
done