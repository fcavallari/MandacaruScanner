#!/usr/bin/env bash
# ./toggle.sh checkout block|classic   which page is the store's checkout page
# ./toggle.sh skimmer on|off           the opt-in test skimmer (option pnakotic_test_skimmer)
set -euo pipefail
cd "$(dirname "$0")"
dc() { docker compose -p pnakotic-woo-testbed "$@"; }
wp() { dc run --rm -T wpcli "$@"; }

case "${1:-} ${2:-}" in
  "checkout block"|"checkout classic")
    slug=checkout; [ "$2" = classic ] && slug=checkout-classic
    id="$(wp post list --post_type=page --name="$slug" --field=ID | tr -d '\r')"
    wp option update woocommerce_checkout_page_id "$id"
    ;;
  "skimmer on")  wp option update pnakotic_test_skimmer 1 ;;
  "skimmer off") wp option update pnakotic_test_skimmer 0 ;;
  *) echo "usage: $0 checkout block|classic | skimmer on|off" >&2; exit 2 ;;
esac
