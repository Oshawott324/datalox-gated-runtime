#!/usr/bin/env bash
set -euo pipefail

API_BASE="https://api.easypost.com/v2"
SHIPMENT_REFERENCE="datalox-easypost-auth-probe-v2"
PICKUP_REFERENCE="datalox-easypost-auth-probe-pickup-v2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROBE_CONFIG="$REPO_ROOT/probes/easypost.json"
DATALOX_GATE_BIN="${DATALOX_GATE_BIN:-datalox-gate}"

usage() {
  cat <<'EOF'
Usage:
  easypost-sandbox.sh check
  easypost-sandbox.sh seed --confirm-test-writes
  easypost-sandbox.sh seed-and-probe --confirm-test-writes --out RUN_DIR

The seed commands make EasyPost test-mode writes directly, outside Datalox.
They create or reuse one shipment, buy its USPS GroundAdvantage test label,
create or reuse one batch, attempt a pickup quote, and print the available IDs.
Pickup detail is omitted from the rendered probe when the provider returns 422.
EASYPOST_TEST_KEY is read from the environment and is never written to disk.
EOF
}

die() {
  printf 'easypost-sandbox: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

basic_credential() {
  printf '%s:' "$EASYPOST_TEST_KEY" | base64 | tr -d '\r\n'
}

api_request() {
  local method="$1"
  local path="$2"
  local payload="${3:-}"
  local allow_404="${4:-false}"
  local auth_config output body status
  local -a args

  auth_config="header = \"Authorization: Basic $(basic_credential)\""
  args=(
    --silent
    --show-error
    --request "$method"
    --url "$API_BASE$path"
    --header 'Accept: application/json'
    --write-out $'\n%{http_code}'
  )
  if [[ -n "$payload" ]]; then
    args+=(--header 'Content-Type: application/json' --data-binary "$payload")
  fi

  if ! output="$(printf '%s\n' "$auth_config" | env -u EASYPOST_TEST_KEY curl --config - "${args[@]}")"; then
    printf 'easypost-sandbox: %s %s failed at the transport layer\n' "$method" "$path" >&2
    return 1
  fi
  status="${output##*$'\n'}"
  body="${output%$'\n'*}"

  if [[ "$status" == "404" && "$allow_404" == "true" ]]; then
    return 44
  fi
  if [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
    printf 'easypost-sandbox: %s %s returned HTTP %s\n' "$method" "$path" "$status" >&2
    printf '%s\n' "$body" >&2
    [[ "$status" == "422" ]] && return 42
    return 1
  fi
  printf '%s' "$body"
}

require_test_mode() {
  local object_name="$1"
  local payload="$2"
  local mode
  mode="$(jq -er '.mode' <<<"$payload")" || die "$object_name response has no mode"
  [[ "$mode" == "test" ]] || die "$object_name response mode is $mode; refusing further writes"
}

required_id() {
  local object_name="$1"
  local expression="$2"
  local prefix="$3"
  local payload="$4"
  local id
  id="$(jq -er "$expression" <<<"$payload")" || die "$object_name response has no ID"
  [[ "$id" == "$prefix"* ]] || die "$object_name returned unexpected ID: $id"
  printf '%s' "$id"
}

pickup_day() {
  local now
  now="$(date -u +%s)"
  jq -nr --argjson now "$now" '
    ($now + 172800) as $candidate
    | ($candidate | strftime("%w") | tonumber) as $weekday
    | ($candidate + if $weekday == 6 then 172800 elif $weekday == 0 then 86400 else 0 end)
    | strftime("%Y-%m-%d")
  '
}

seed_objects() {
  local shipment shipment_id rate_id batch batch_id pickup pickup_id
  local address_id parcel_id tracker_id day shipment_payload buy_payload batch_payload pickup_payload
  local pickup_status

  printf 'easypost-sandbox: resolving deterministic shipment reference\n' >&2
  if shipment="$(api_request GET "/shipments/$SHIPMENT_REFERENCE" '' true)"; then
    require_test_mode shipment "$shipment"
  else
    [[ "$?" == "44" ]] || die "unexpected shipment lookup failure"
    shipment_payload="$(jq -n --arg reference "$SHIPMENT_REFERENCE" '
      {
        shipment: {
          reference: $reference,
          from_address: {
            name: "Dr. Steve Brule",
            street1: "179 N Harbor Dr",
            city: "Redondo Beach",
            state: "CA",
            zip: "90277",
            country: "US",
            phone: "8573875756"
          },
          to_address: {
            company: "EasyPost",
            street1: "417 Montgomery St",
            street2: "Floor 5",
            city: "San Francisco",
            state: "CA",
            zip: "94104",
            country: "US",
            phone: "415-123-4567"
          },
          parcel: {length: 8, width: 6, height: 4, weight: 16}
        }
      }
    ')" || return $?
    shipment="$(api_request POST '/shipments' "$shipment_payload")" || return $?
    require_test_mode shipment "$shipment"
  fi

  shipment_id="$(required_id shipment '.id' 'shp_' "$shipment")" || return $?
  if [[ "$(jq -r '.postage_label == null' <<<"$shipment")" == "true" ]]; then
    rate_id="$(jq -er '
      [.rates[] | select(.carrier == "USPS" and .service == "GroundAdvantage")]
      | sort_by([(.rate | tonumber), .id])
      | .[0].id
    ' <<<"$shipment")" || die "shipment has no USPS GroundAdvantage test rate"
    buy_payload="$(jq -n --arg rate_id "$rate_id" '{rate: {id: $rate_id}}')" || return $?
    printf 'easypost-sandbox: buying test-mode USPS GroundAdvantage label\n' >&2
    shipment="$(api_request POST "/shipments/$shipment_id/buy" "$buy_payload")" || return $?
    require_test_mode shipment "$shipment"
  fi

  shipment="$(api_request GET "/shipments/$shipment_id")" || return $?
  require_test_mode shipment "$shipment"
  address_id="$(required_id address '.from_address.id' 'adr_' "$shipment")" || return $?
  parcel_id="$(required_id parcel '.parcel.id' 'prcl_' "$shipment")" || return $?
  tracker_id="$(required_id tracker '.tracker.id' 'trk_' "$shipment")" || return $?

  batch_id="$(jq -r '.batch_id // ""' <<<"$shipment")" || return $?
  if [[ -n "$batch_id" ]]; then
    batch="$(api_request GET "/batches/$batch_id")" || return $?
    require_test_mode batch "$batch"
  else
    batch_payload="$(jq -n --arg shipment_id "$shipment_id" \
      '{batch: {shipments: [{id: $shipment_id}]}}')" || return $?
    printf 'easypost-sandbox: creating test-mode batch\n' >&2
    batch="$(api_request POST '/batches' "$batch_payload")" || return $?
    require_test_mode batch "$batch"
    batch_id="$(required_id batch '.id' 'batch_' "$batch")" || return $?
  fi
  [[ "$batch_id" == batch_* ]] || die "batch returned unexpected ID: $batch_id"

  printf 'easypost-sandbox: resolving deterministic pickup reference\n' >&2
  if pickup="$(api_request GET "/pickups/$PICKUP_REFERENCE" '' true)"; then
    require_test_mode pickup "$pickup"
  else
    [[ "$?" == "44" ]] || die "unexpected pickup lookup failure"
    day="$(pickup_day)" || return $?
    pickup_payload="$(jq -n \
      --arg reference "$PICKUP_REFERENCE" \
      --arg shipment_id "$shipment_id" \
      --arg address_id "$address_id" \
      --arg min_datetime "${day}T10:00:00Z" \
      --arg max_datetime "${day}T17:00:00Z" '
      {
        pickup: {
          reference: $reference,
          min_datetime: $min_datetime,
          max_datetime: $max_datetime,
          shipment: $shipment_id,
          address: $address_id,
          is_account_address: false,
          instructions: "Datalox EasyPost sandbox probe fixture"
        }
      }
    ')" || return $?
    printf 'easypost-sandbox: creating test-mode pickup quote; no pickup is purchased\n' >&2
    if pickup="$(api_request POST '/pickups' "$pickup_payload")"; then
      require_test_mode pickup "$pickup"
    else
      pickup_status=$?
      [[ "$pickup_status" == "42" ]] || return "$pickup_status"
      printf 'easypost-sandbox: pickup detail unavailable; continuing with collection GET only\n' >&2
      pickup=""
    fi
  fi
  if [[ -n "$pickup" ]]; then
    pickup_id="$(required_id pickup '.id' 'pickup_' "$pickup")" || return $?
  else
    pickup_id=""
  fi

  jq -n \
    --arg address_id "$address_id" \
    --arg parcel_id "$parcel_id" \
    --arg shipment_id "$shipment_id" \
    --arg tracker_id "$tracker_id" \
    --arg batch_id "$batch_id" \
    --arg pickup_id "$pickup_id" \
    '{
      address_id: $address_id,
      parcel_id: $parcel_id,
      shipment_id: $shipment_id,
      tracker_id: $tracker_id,
      batch_id: $batch_id,
      pickup_id: (if $pickup_id == "" then null else $pickup_id end)
    }'
}

render_probe_config() {
  local ids="$1"
  local output_path="$2"
  local address_id parcel_id shipment_id tracker_id batch_id pickup_id

  address_id="$(jq -er '.address_id' <<<"$ids")"
  parcel_id="$(jq -er '.parcel_id' <<<"$ids")"
  shipment_id="$(jq -er '.shipment_id' <<<"$ids")"
  tracker_id="$(jq -er '.tracker_id' <<<"$ids")"
  batch_id="$(jq -er '.batch_id' <<<"$ids")"
  pickup_id="$(jq -r '.pickup_id // ""' <<<"$ids")"

  jq \
    --arg address_id "$address_id" \
    --arg parcel_id "$parcel_id" \
    --arg shipment_id "$shipment_id" \
    --arg tracker_id "$tracker_id" \
    --arg batch_id "$batch_id" \
    --arg pickup_id "$pickup_id" '
    (if $pickup_id == "" then
      .probe_requests |= map(select(.path | contains("__EASYPOST_PICKUP_ID__") | not))
    else . end)
    | walk(
      if type == "string" then
        gsub("__EASYPOST_ADDRESS_ID__"; $address_id)
        | gsub("__EASYPOST_PARCEL_ID__"; $parcel_id)
        | gsub("__EASYPOST_SHIPMENT_ID__"; $shipment_id)
        | gsub("__EASYPOST_TRACKER_ID__"; $tracker_id)
        | gsub("__EASYPOST_BATCH_ID__"; $batch_id)
        | gsub("__EASYPOST_PICKUP_ID__"; $pickup_id)
      else . end
    )
    | .rate_budget.max_requests = (.probe_requests | length)
  ' "$PROBE_CONFIG" >"$output_path"

  if rg -n '__EASYPOST_[A-Z_]+__' "$output_path" >/dev/null 2>&1; then
    die "rendered probe config still contains unresolved EasyPost IDs"
  fi
}

check_config() {
  local request_count placeholder_count
  jq -e . "$PROBE_CONFIG" >/dev/null
  request_count="$(jq '.probe_requests | length' "$PROBE_CONFIG")"
  [[ "$request_count" == "13" ]] || die "expected 13 probe requests, found $request_count"
  [[ "$(jq -r '[.probe_requests[].method] | unique | join(",")' "$PROBE_CONFIG")" == "GET" ]] || {
    die "probe config contains a non-GET request"
  }
  [[ "$(jq '.rate_budget.max_requests' "$PROBE_CONFIG")" == "$request_count" ]] || {
    die "rate budget does not equal probe request count"
  }
  placeholder_count="$(rg -o '__EASYPOST_[A-Z_]+__' "$PROBE_CONFIG" | sort -u | wc -l | tr -d ' ')"
  [[ "$placeholder_count" == "6" ]] || die "expected 6 seeded-ID placeholders, found $placeholder_count"
  printf 'easypost-sandbox: config structure passed (%s GET requests, %s seeded IDs)\n' \
    "$request_count" "$placeholder_count"
}

command_name="${1:-}"
[[ -n "$command_name" ]] || {
  usage
  exit 1
}
shift

confirm_test_writes=false
out_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm-test-writes)
      confirm_test_writes=true
      shift
      ;;
    --out)
      [[ $# -ge 2 ]] || die "--out requires a path"
      out_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

require_command jq
require_command rg

case "$command_name" in
  check)
    check_config
    ;;
  seed|seed-and-probe)
    require_command base64
    require_command curl
    require_command env
    [[ "$confirm_test_writes" == "true" ]] || {
      die "provider writes require --confirm-test-writes"
    }
    [[ -n "${EASYPOST_TEST_KEY:-}" ]] || die "EASYPOST_TEST_KEY is not set"

    ids="$(seed_objects)" || exit $?
    if [[ "$command_name" == "seed" ]]; then
      printf '%s\n' "$ids"
      exit 0
    fi

    [[ -n "$out_dir" ]] || die "seed-and-probe requires --out RUN_DIR"
    require_command "$DATALOX_GATE_BIN"
    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/datalox-easypost.XXXXXX")"
    trap 'rm -rf "$temp_dir"' EXIT
    rendered_config="$temp_dir/easypost.json"
    render_probe_config "$ids" "$rendered_config"
    easypost_basic_credential="$(basic_credential)"
    env -u EASYPOST_TEST_KEY \
      EASYPOST_BASIC_CREDENTIAL="$easypost_basic_credential" \
      "$DATALOX_GATE_BIN" provider probe \
      --config "$rendered_config" \
      --out "$out_dir" \
      --json
    unset easypost_basic_credential
    ;;
  *)
    usage
    exit 1
    ;;
esac
