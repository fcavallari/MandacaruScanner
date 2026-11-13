#!/usr/bin/env bash
# ./toggle.sh checkout block|classic   which page is the store's checkout page
# ./toggle.sh gateways extra on|off    cod + bacs (positive control: they create real orders); default off
# ./toggle.sh skimmer on|off           the opt-in test skimmer (option mandacaru_test_skimmer)
set -euo pipefail
cd "$(dirname "$0")"
dc() { docker compose -p mandacaru-woo-testbed "$@"; }
wp() { dc run --rm -T wpcli "$@"; }

case "${1:-} ${2:-}" in
  "checkout block"|"checkout classic")
    slug=checkout; [ "$2" = classic ] && slug=checkout-classic
    id="$(wp post list --post_type=page --name="$slug" --field=ID | tr -d '\r')"
    wp option update woocommerce_checkout_page_id "$id"
    ;;
  "gateways extra")
    case "${3:-}" in on) v=true ;; off) v=false ;; *) echo "usage: $0 gateways extra on|off" >&2; exit 2 ;; esac
    for g in cod bacs; do wp wc payment_gateway update "$g" --enabled="$v" --user=admin >/dev/null; done
    echo "cod and bacs enabled=$v"
    ;;
  "skimmer on")  wp option update mandacaru_test_skimmer 1 ;;
  "skimmer off") wp option update mandacaru_test_skimmer 0 ;;
  *) echo "usage: $0 checkout block|classic | skimmer on|off" >&2; exit 2 ;;
esac
