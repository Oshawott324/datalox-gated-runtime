#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMAND="${1:-help}"
CONFIG_TEMPLATE="$ROOT_DIR/probes/pagerduty.json"
WORK_DIR="${PAGERDUTY_WORK_DIR:-$ROOT_DIR/.tmp/pagerduty-sandbox}"
IDS_FILE="$WORK_DIR/ids.json"
RENDERED_CONFIG="$WORK_DIR/pagerduty.probe.rendered.json"
PROBE_OUT="${PAGERDUTY_PROBE_OUT:-$WORK_DIR/probe-run}"
API_BASE_URL="https://api.pagerduty.com"

TEAM_NAME="Datalox PagerDuty Probe Team v1"
SCHEDULE_NAME="Datalox PagerDuty Probe Schedule v1"
ESCALATION_POLICY_NAME="Datalox PagerDuty Probe Escalation Policy v1"
SERVICE_NAME="Datalox PagerDuty Probe Service v1"
MAINTENANCE_DESCRIPTION="Datalox PagerDuty Probe Maintenance Window v1"
INCIDENT_TITLE="Datalox PagerDuty Probe Incident v1"
INCIDENT_KEY="datalox-pagerduty-probe-v1"

AUTHORIZATION=""
API_STATUS=""
API_BODY=""
LOOKUP_ID=""
LOOKUP_STATUS=""

USER_ID=""
TEAM_ID=""
SCHEDULE_ID=""
ESCALATION_POLICY_ID=""
SERVICE_ID=""
MAINTENANCE_WINDOW_ID=""
INCIDENT_ID=""
ALERT_ID=""
ORCHESTRATION_ID=""
RULESET_ID=""
RULE_ID=""
SERVICE_RULE_ID=""
FROM_EMAIL="${PAGERDUTY_FROM_EMAIL:-}"

umask 077

fail() {
  local code="$1"
  local message="$2"
  jq -cn \
    --arg code "$code" \
    --arg message "$message" \
    '{status:"error",error:{code:$code,message:$message}}' >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing_command" "Required command is not installed: $1"
}

urlencode() {
  jq -nr --arg value "$1" '$value | @uri'
}

prepare_auth() {
  [[ -n "${PAGERDUTY_TOKEN:-}" ]] || \
    fail "missing_auth_env" "Set PAGERDUTY_TOKEN in the environment."

  case "${PAGERDUTY_AUTH_KIND:-api_token}" in
    api_token)
      AUTHORIZATION="Token token=${PAGERDUTY_TOKEN}"
      ;;
    oauth_bearer)
      AUTHORIZATION="Bearer ${PAGERDUTY_TOKEN}"
      ;;
    *)
      fail \
        "invalid_auth_kind" \
        "PAGERDUTY_AUTH_KIND must be api_token or oauth_bearer."
      ;;
  esac

  if [[ "$AUTHORIZATION" == *$'\n'* || "$AUTHORIZATION" == *$'\r'* || "$AUTHORIZATION" == *'"'* ]]; then
    fail "invalid_auth_value" "PAGERDUTY_TOKEN contains characters unsafe for an HTTP header."
  fi
  if [[ -n "$FROM_EMAIL" && ( "$FROM_EMAIL" == *$'\n'* || "$FROM_EMAIL" == *$'\r'* ) ]]; then
    fail "invalid_from_email" "PAGERDUTY_FROM_EMAIL contains a newline."
  fi
  unset PAGERDUTY_TOKEN
}

api_request() {
  local method="$1"
  local resource="$2"
  local payload="${3:-}"
  local from_email="${4:-}"
  local raw
  local curl_args=(
    --silent
    --show-error
    --request "$method"
    --url "$API_BASE_URL$resource"
    --proto '=https'
    --tlsv1.2
    --header 'Accept: application/vnd.pagerduty+json;version=2'
    --header 'Content-Type: application/json'
    --write-out $'\n%{http_code}'
  )

  if [[ -n "$from_email" ]]; then
    curl_args+=(--header "From: $from_email")
  fi

  if [[ -n "$payload" ]]; then
    if ! raw="$(
      printf '%s' "$payload" |
        curl "${curl_args[@]}" \
          --data-binary @- \
          --config <(printf 'header = "Authorization: %s"\n' "$AUTHORIZATION")
    )"; then
      fail "pagerduty_transport_error" "$method $resource failed before an HTTP response."
    fi
  elif ! raw="$(
    curl "${curl_args[@]}" \
      --config <(printf 'header = "Authorization: %s"\n' "$AUTHORIZATION")
  )"; then
    fail "pagerduty_transport_error" "$method $resource failed before an HTTP response."
  fi

  API_STATUS="${raw##*$'\n'}"
  API_BODY="${raw%$'\n'*}"
  [[ "$API_STATUS" =~ ^[0-9]{3}$ ]] || \
    fail "invalid_http_status" "$method $resource returned an unreadable HTTP status."
}

require_json_body() {
  local context="$1"
  jq -e . >/dev/null 2>&1 <<<"$API_BODY" || \
    fail "invalid_provider_json" "$context returned a non-JSON response."
}

provider_error_message() {
  jq -r '.error.message // .message // empty' <<<"$API_BODY" 2>/dev/null || true
}

require_status() {
  local expected="$1"
  local context="$2"
  local provider_message
  if [[ "$API_STATUS" == "$expected" ]]; then
    require_json_body "$context"
    return
  fi
  provider_message="$(provider_error_message)"
  if [[ -n "$provider_message" ]]; then
    fail \
      "pagerduty_api_error" \
      "$context returned HTTP $API_STATUS: $provider_message"
  fi
  fail "pagerduty_api_error" "$context returned HTTP $API_STATUS."
}

lookup_named_resource() {
  local resource="$1"
  local collection="$2"
  local value="$3"
  api_request GET "$resource"
  LOOKUP_STATUS="$API_STATUS"
  LOOKUP_ID=""
  if [[ "$API_STATUS" == "200" ]]; then
    require_json_body "GET $resource"
    LOOKUP_ID="$(
      jq -r \
        --arg collection "$collection" \
        --arg value "$value" \
        '[.[$collection][]? | select(.name == $value or .description == $value)]
         | sort_by(.id) | .[0].id // empty' <<<"$API_BODY"
    )"
    return
  fi
  case "$API_STATUS" in
    402|403|404)
      return
      ;;
  esac
  require_status 200 "GET $resource"
}

resolve_user() {
  if [[ -n "$FROM_EMAIL" ]]; then
    local encoded_email
    encoded_email="$(urlencode "$FROM_EMAIL")"
    api_request GET "/users?query=$encoded_email&limit=100"
    require_status 200 "Find PagerDuty authoring user"
    USER_ID="$(
      jq -r \
        --arg email "${FROM_EMAIL,,}" \
        '[.users[]? | select((.email | ascii_downcase) == $email)]
         | sort_by(.id) | .[0].id // empty' <<<"$API_BODY"
    )"
    [[ -n "$USER_ID" ]] || \
      fail "authoring_user_not_found" "PAGERDUTY_FROM_EMAIL does not match an account user."
    return
  fi

  api_request GET "/users/me"
  if [[ "$API_STATUS" != "200" ]]; then
    fail \
      "authoring_user_required" \
      "Set PAGERDUTY_FROM_EMAIL when the token cannot resolve GET /users/me."
  fi
  require_json_body "Get current PagerDuty user"
  USER_ID="$(jq -r '.user.id // empty' <<<"$API_BODY")"
  FROM_EMAIL="$(jq -r '.user.email // empty' <<<"$API_BODY")"
  [[ -n "$USER_ID" && -n "$FROM_EMAIL" ]] || \
    fail "invalid_current_user" "GET /users/me did not return both user ID and email."
}

discover_or_author_team() {
  local create="$1"
  local encoded_name payload
  encoded_name="$(urlencode "$TEAM_NAME")"
  lookup_named_resource "/teams?query=$encoded_name&limit=100" teams "$TEAM_NAME"
  TEAM_ID="$LOOKUP_ID"
  [[ -n "$TEAM_ID" || "$create" == "true" ]] || return

  if [[ -z "$TEAM_ID" && "$LOOKUP_STATUS" != "200" ]]; then
    return
  fi
  [[ -n "$TEAM_ID" ]] && return

  payload="$(
    jq -cn \
      --arg name "$TEAM_NAME" \
      '{team:{type:"team",name:$name,description:"Dedicated PagerDuty trial-account probe team."}}'
  )"
  api_request POST "/teams" "$payload"
  case "$API_STATUS" in
    201)
      require_json_body "Create PagerDuty probe team"
      TEAM_ID="$(jq -r '.team.id // empty' <<<"$API_BODY")"
      [[ -n "$TEAM_ID" ]] || fail "missing_created_id" "Created team has no ID."
      ;;
    402|403)
      TEAM_ID=""
      ;;
    *)
      require_status 201 "Create PagerDuty probe team"
      ;;
  esac
}

discover_or_author_schedule() {
  local create="$1"
  local encoded_name payload
  encoded_name="$(urlencode "$SCHEDULE_NAME")"
  lookup_named_resource "/schedules?query=$encoded_name&limit=100" schedules "$SCHEDULE_NAME"
  SCHEDULE_ID="$LOOKUP_ID"
  [[ -n "$SCHEDULE_ID" || "$create" == "true" ]] || return
  [[ "$LOOKUP_STATUS" == "200" ]] || \
    fail "schedule_surface_unavailable" "The trial account cannot list schedules (HTTP $LOOKUP_STATUS)."
  [[ -n "$SCHEDULE_ID" ]] && return

  payload="$(
    jq -cn \
      --arg name "$SCHEDULE_NAME" \
      --arg user_id "$USER_ID" \
      '{schedule:{
        type:"schedule",
        name:$name,
        description:"Dedicated PagerDuty trial-account probe schedule.",
        time_zone:"UTC",
        schedule_layers:[{
          name:"Datalox weekly rotation",
          start:"2026-01-01T00:00:00Z",
          rotation_virtual_start:"2026-01-01T00:00:00Z",
          rotation_turn_length_seconds:604800,
          users:[{user:{id:$user_id,type:"user_reference"}}]
        }]
      }}'
  )"
  api_request POST "/schedules" "$payload"
  require_status 201 "Create PagerDuty probe schedule"
  SCHEDULE_ID="$(jq -r '.schedule.id // empty' <<<"$API_BODY")"
  [[ -n "$SCHEDULE_ID" ]] || fail "missing_created_id" "Created schedule has no ID."
}

discover_or_author_escalation_policy() {
  local create="$1"
  local encoded_name payload
  encoded_name="$(urlencode "$ESCALATION_POLICY_NAME")"
  lookup_named_resource \
    "/escalation_policies?query=$encoded_name&limit=100" \
    escalation_policies \
    "$ESCALATION_POLICY_NAME"
  ESCALATION_POLICY_ID="$LOOKUP_ID"
  [[ -n "$ESCALATION_POLICY_ID" || "$create" == "true" ]] || return
  [[ "$LOOKUP_STATUS" == "200" ]] || \
    fail \
      "escalation_policy_surface_unavailable" \
      "The trial account cannot list escalation policies (HTTP $LOOKUP_STATUS)."
  [[ -n "$ESCALATION_POLICY_ID" ]] && return
  [[ -n "$SCHEDULE_ID" ]] || \
    fail "missing_schedule_id" "Authoring an escalation policy requires the seeded schedule."

  payload="$(
    jq -cn \
      --arg name "$ESCALATION_POLICY_NAME" \
      --arg schedule_id "$SCHEDULE_ID" \
      --arg team_id "$TEAM_ID" \
      '{escalation_policy:{
        type:"escalation_policy",
        name:$name,
        description:"Dedicated PagerDuty trial-account probe escalation policy.",
        num_loops:0,
        escalation_rules:[{
          escalation_delay_in_minutes:30,
          targets:[{id:$schedule_id,type:"schedule_reference"}]
        }]
      }}
      | if $team_id == "" then .
        else .escalation_policy.teams = [{id:$team_id,type:"team_reference"}]
        end'
  )"
  api_request POST "/escalation_policies" "$payload" "$FROM_EMAIL"
  require_status 201 "Create PagerDuty probe escalation policy"
  ESCALATION_POLICY_ID="$(jq -r '.escalation_policy.id // empty' <<<"$API_BODY")"
  [[ -n "$ESCALATION_POLICY_ID" ]] || \
    fail "missing_created_id" "Created escalation policy has no ID."
}

discover_or_author_service() {
  local create="$1"
  local encoded_name payload
  encoded_name="$(urlencode "$SERVICE_NAME")"
  lookup_named_resource "/services?query=$encoded_name&limit=100" services "$SERVICE_NAME"
  SERVICE_ID="$LOOKUP_ID"
  [[ -n "$SERVICE_ID" || "$create" == "true" ]] || return
  [[ "$LOOKUP_STATUS" == "200" ]] || \
    fail "service_surface_unavailable" "The trial account cannot list services (HTTP $LOOKUP_STATUS)."
  [[ -n "$SERVICE_ID" ]] && return
  [[ -n "$ESCALATION_POLICY_ID" ]] || \
    fail "missing_escalation_policy_id" "Authoring a service requires the seeded escalation policy."

  payload="$(
    jq -cn \
      --arg name "$SERVICE_NAME" \
      --arg escalation_policy_id "$ESCALATION_POLICY_ID" \
      '{service:{
        type:"service",
        name:$name,
        description:"Dedicated PagerDuty trial-account probe service.",
        status:"active",
        alert_creation:"create_alerts_and_incidents",
        escalation_policy:{id:$escalation_policy_id,type:"escalation_policy_reference"}
      }}'
  )"
  api_request POST "/services" "$payload"
  require_status 201 "Create PagerDuty probe service"
  SERVICE_ID="$(jq -r '.service.id // empty' <<<"$API_BODY")"
  [[ -n "$SERVICE_ID" ]] || fail "missing_created_id" "Created service has no ID."
}

discover_or_author_maintenance_window() {
  local create="$1"
  local encoded_description payload
  encoded_description="$(urlencode "$MAINTENANCE_DESCRIPTION")"
  lookup_named_resource \
    "/maintenance_windows?query=$encoded_description&limit=100" \
    maintenance_windows \
    "$MAINTENANCE_DESCRIPTION"
  MAINTENANCE_WINDOW_ID="$LOOKUP_ID"
  [[ -n "$MAINTENANCE_WINDOW_ID" || "$create" == "true" ]] || return
  [[ "$LOOKUP_STATUS" == "200" ]] || \
    fail \
      "maintenance_window_surface_unavailable" \
      "The trial account cannot list maintenance windows (HTTP $LOOKUP_STATUS)."
  [[ -n "$MAINTENANCE_WINDOW_ID" ]] && return
  [[ -n "$SERVICE_ID" ]] || \
    fail "missing_service_id" "Authoring a maintenance window requires the seeded service."

  payload="$(
    jq -cn \
      --arg description "$MAINTENANCE_DESCRIPTION" \
      --arg service_id "$SERVICE_ID" \
      '{maintenance_window:{
        type:"maintenance_window",
        start_time:"2035-01-01T00:00:00Z",
        end_time:"2035-01-02T00:00:00Z",
        description:$description,
        services:[{id:$service_id,type:"service_reference"}]
      }}'
  )"
  api_request POST "/maintenance_windows" "$payload" "$FROM_EMAIL"
  require_status 201 "Create PagerDuty probe maintenance window"
  MAINTENANCE_WINDOW_ID="$(jq -r '.maintenance_window.id // empty' <<<"$API_BODY")"
  [[ -n "$MAINTENANCE_WINDOW_ID" ]] || \
    fail "missing_created_id" "Created maintenance window has no ID."
}

discover_or_author_incident() {
  local create="$1"
  local encoded_key payload
  encoded_key="$(urlencode "$INCIDENT_KEY")"
  api_request GET "/incidents?incident_key=$encoded_key&date_range=all&limit=100"
  if [[ "$API_STATUS" == "200" ]]; then
    require_json_body "Find PagerDuty probe incident"
    INCIDENT_ID="$(
      jq -r \
        --arg incident_key "$INCIDENT_KEY" \
        '[.incidents[]? | select(.incident_key == $incident_key)]
         | sort_by(.id) | .[0].id // empty' <<<"$API_BODY"
    )"
  elif [[ "$create" == "true" ]]; then
    require_status 200 "Find PagerDuty probe incident"
  fi
  [[ -n "$INCIDENT_ID" || "$create" == "true" ]] || return
  [[ -n "$INCIDENT_ID" ]] && return
  [[ -n "$SERVICE_ID" ]] || \
    fail "missing_service_id" "Authoring an incident requires the seeded service."

  payload="$(
    jq -cn \
      --arg title "$INCIDENT_TITLE" \
      --arg incident_key "$INCIDENT_KEY" \
      --arg service_id "$SERVICE_ID" \
      '{incident:{
        type:"incident",
        title:$title,
        incident_key:$incident_key,
        urgency:"low",
        service:{id:$service_id,type:"service_reference"},
        body:{type:"incident_body",details:"Synthetic trial-account object for safe GET capture."}
      }}'
  )"
  api_request POST "/incidents" "$payload" "$FROM_EMAIL"
  require_status 201 "Create PagerDuty probe incident"
  INCIDENT_ID="$(jq -r '.incident.id // empty' <<<"$API_BODY")"
  [[ -n "$INCIDENT_ID" ]] || fail "missing_created_id" "Created incident has no ID."
}

discover_optional_detail_ids() {
  if [[ -n "$INCIDENT_ID" ]]; then
    api_request GET "/incidents/$INCIDENT_ID/alerts?limit=25"
    if [[ "$API_STATUS" == "200" ]]; then
      require_json_body "List alerts for PagerDuty probe incident"
      ALERT_ID="$(jq -r '[.alerts[]?] | sort_by(.id) | .[0].id // empty' <<<"$API_BODY")"
    fi
  fi

  if [[ -n "$SERVICE_ID" ]]; then
    api_request GET "/services/$SERVICE_ID/rules?limit=25"
    if [[ "$API_STATUS" == "200" ]]; then
      require_json_body "List service event rules"
      SERVICE_RULE_ID="$(jq -r '[.rules[]?] | sort_by(.id) | .[0].id // empty' <<<"$API_BODY")"
    fi
  fi

  api_request GET "/event_orchestrations?limit=25"
  if [[ "$API_STATUS" == "200" ]]; then
    require_json_body "List event orchestrations"
    ORCHESTRATION_ID="$(
      jq -r '[.orchestrations[]?] | sort_by(.id) | .[0].id // empty' <<<"$API_BODY"
    )"
  fi

  api_request GET "/rulesets?limit=25"
  if [[ "$API_STATUS" == "200" ]]; then
    require_json_body "List rulesets"
    RULESET_ID="$(jq -r '[.rulesets[]?] | sort_by(.id) | .[0].id // empty' <<<"$API_BODY")"
  fi
  if [[ -n "$RULESET_ID" ]]; then
    api_request GET "/rulesets/$RULESET_ID/rules?limit=25"
    if [[ "$API_STATUS" == "200" ]]; then
      require_json_body "List ruleset event rules"
      RULE_ID="$(jq -r '[.rules[]?] | sort_by(.id) | .[0].id // empty' <<<"$API_BODY")"
    fi
  fi
}

write_ids_manifest() {
  mkdir -p "$WORK_DIR"
  chmod 700 "$WORK_DIR"
  local temporary
  temporary="$(mktemp "$WORK_DIR/ids.XXXXXX")"
  jq -n \
    --arg user_id "$USER_ID" \
    --arg team_id "$TEAM_ID" \
    --arg schedule_id "$SCHEDULE_ID" \
    --arg escalation_policy_id "$ESCALATION_POLICY_ID" \
    --arg service_id "$SERVICE_ID" \
    --arg maintenance_window_id "$MAINTENANCE_WINDOW_ID" \
    --arg incident_id "$INCIDENT_ID" \
    --arg alert_id "$ALERT_ID" \
    --arg orchestration_id "$ORCHESTRATION_ID" \
    --arg ruleset_id "$RULESET_ID" \
    --arg rule_id "$RULE_ID" \
    --arg service_rule_id "$SERVICE_RULE_ID" \
    --arg team_name "$TEAM_NAME" \
    --arg schedule_name "$SCHEDULE_NAME" \
    --arg escalation_policy_name "$ESCALATION_POLICY_NAME" \
    --arg service_name "$SERVICE_NAME" \
    --arg maintenance_description "$MAINTENANCE_DESCRIPTION" \
    --arg incident_key "$INCIDENT_KEY" \
    '
      def optional: if . == "" then null else . end;
      {
        schema_version: 1,
        markers: {
          team_name: $team_name,
          schedule_name: $schedule_name,
          escalation_policy_name: $escalation_policy_name,
          service_name: $service_name,
          maintenance_description: $maintenance_description,
          incident_key: $incident_key
        },
        ids: {
          user_id: ($user_id | optional),
          team_id: ($team_id | optional),
          schedule_id: ($schedule_id | optional),
          escalation_policy_id: ($escalation_policy_id | optional),
          service_id: ($service_id | optional),
          maintenance_window_id: ($maintenance_window_id | optional),
          incident_id: ($incident_id | optional),
          alert_id: ($alert_id | optional),
          orchestration_id: ($orchestration_id | optional),
          ruleset_id: ($ruleset_id | optional),
          rule_id: ($rule_id | optional),
          service_rule_id: ($service_rule_id | optional)
        }
      }
    ' >"$temporary"
  mv "$temporary" "$IDS_FILE"
}

render_config() {
  local template_count rendered_count temporary
  template_count="$(jq '.probe_requests | length' "$CONFIG_TEMPLATE")"
  temporary="$(mktemp "$WORK_DIR/pagerduty.probe.XXXXXX")"
  jq --slurpfile manifest "$IDS_FILE" '
    def substitute($value; $replacements):
      reduce ($replacements | to_entries[]) as $entry
        ($value;
          if $entry.value == null then .
          else gsub($entry.key; $entry.value)
          end);
    ($manifest[0].ids | {
      "__USER_ID__": .user_id,
      "__TEAM_ID__": .team_id,
      "__SCHEDULE_ID__": .schedule_id,
      "__ESCALATION_POLICY_ID__": .escalation_policy_id,
      "__SERVICE_ID__": .service_id,
      "__MAINTENANCE_WINDOW_ID__": .maintenance_window_id,
      "__INCIDENT_ID__": .incident_id,
      "__ALERT_ID__": .alert_id,
      "__ORCHESTRATION_ID__": .orchestration_id,
      "__RULESET_ID__": .ruleset_id,
      "__RULE_ID__": .rule_id,
      "__SERVICE_RULE_ID__": .service_rule_id
    }) as $replacements
    | .probe_requests |= map(
        .path = substitute(.path; $replacements)
        | .query |= with_entries(.value = substitute(.value; $replacements))
      )
    | .probe_requests |= map(
        select(
          (.path | test("__[A-Z0-9_]+__") | not)
          and (.query | tojson | test("__[A-Z0-9_]+__") | not)
        )
      )
    | .rate_budget.max_requests = (.probe_requests | length)
  ' "$CONFIG_TEMPLATE" >"$temporary"
  mv "$temporary" "$RENDERED_CONFIG"
  rendered_count="$(jq '.probe_requests | length' "$RENDERED_CONFIG")"
  jq -cn \
    --arg command "$COMMAND" \
    --arg ids_file "$IDS_FILE" \
    --arg rendered_config "$RENDERED_CONFIG" \
    --argjson template_requests "$template_count" \
    --argjson rendered_requests "$rendered_count" \
    '{
      status:"completed",
      command:$command,
      authoring_writes:($command == "author"),
      ids_file:$ids_file,
      rendered_config:$rendered_config,
      template_requests:$template_requests,
      rendered_requests:$rendered_requests,
      omitted_unresolved_detail_requests:($template_requests - $rendered_requests)
    }'
}

prepare_resources() {
  local create="$1"
  prepare_auth
  resolve_user
  discover_or_author_team "$create"
  discover_or_author_schedule "$create"
  discover_or_author_escalation_policy "$create"
  discover_or_author_service "$create"
  discover_or_author_maintenance_window "$create"
  discover_or_author_incident "$create"
  discover_optional_detail_ids
  write_ids_manifest
  render_config
}

gate() {
  PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -m datalox_gated_runtime.cli "$@"
}

validate_config() {
  local config_path="$1"
  PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -c \
      'import sys; from pathlib import Path; from datalox_gated_runtime.provider_probe import load_probe_config; load_probe_config(Path(sys.argv[1]))' \
      "$config_path"
}

validate() {
  need_command bash
  need_command jq
  need_command python3
  bash -n "$0"
  jq -e \
    '(.probe_requests | length) == .rate_budget.max_requests
     and all(.probe_requests[]; .method == "GET")' \
    "$CONFIG_TEMPLATE" >/dev/null
  validate_config "$CONFIG_TEMPLATE"
  if [[ -f "$RENDERED_CONFIG" ]]; then
    jq -e \
      'all(.probe_requests[]; .method == "GET")
       and ([.probe_requests[].path] | join(" ") | test("__[A-Z0-9_]+__") | not)' \
      "$RENDERED_CONFIG" >/dev/null
    validate_config "$RENDERED_CONFIG"
  fi
  jq -cn \
    --arg config "$CONFIG_TEMPLATE" \
    --argjson requests "$(jq '.probe_requests | length' "$CONFIG_TEMPLATE")" \
    '{status:"completed",command:"validate",config:$config,requests:$requests,get_only:true}'
}

probe() {
  need_command jq
  need_command python3
  [[ -f "$RENDERED_CONFIG" ]] || \
    fail "missing_rendered_config" "Run discover or author before probe."
  validate_config "$RENDERED_CONFIG"
  jq -e \
    'all(.probe_requests[]; .method == "GET")
     and ([.probe_requests[].path] | join(" ") | test("__[A-Z0-9_]+__") | not)' \
    "$RENDERED_CONFIG" >/dev/null || \
    fail "invalid_rendered_config" "Rendered probe config is not concrete and GET-only."
  [[ ! -e "$PROBE_OUT" ]] || \
    fail "probe_output_exists" "Choose a new PAGERDUTY_PROBE_OUT; the current path already exists."

  prepare_auth
  export PAGERDUTY_AUTHORIZATION="$AUTHORIZATION"
  gate provider auth-preflight --config "$RENDERED_CONFIG" --json
  gate provider probe --config "$RENDERED_CONFIG" --out "$PROBE_OUT" --json
}

usage() {
  cat <<'USAGE'
Usage: scripts/providers/pagerduty-sandbox.sh {discover|author|probe|validate}

Commands:
  discover  Use PagerDuty GETs outside Datalox to resolve existing deterministic
            seed objects and optional rule/orchestration IDs, then render a
            concrete probe config. Makes no writes.
  author    Create missing deterministic objects directly in a dedicated trial
            account, then render the config. Requires
            PAGERDUTY_CONFIRM_TRIAL_ACCOUNT=1. This may create a low-urgency
            incident and trigger trial-account notifications.
  probe     Run auth preflight and GET-only Datalox live capture with the
            rendered config. Never performs a provider write.
  validate  Parse the tracked config and any rendered config, verify the script,
            request budget, and GET-only invariant. Does not require auth.

Environment:
  PAGERDUTY_TOKEN                  required for discover, author, and probe
  PAGERDUTY_AUTH_KIND              api_token (default) or oauth_bearer
  PAGERDUTY_FROM_EMAIL             required for account tokens that cannot use
                                   GET /users/me; must match an account user
  PAGERDUTY_CONFIRM_TRIAL_ACCOUNT  must be 1 for author
  PAGERDUTY_WORK_DIR               default: .tmp/pagerduty-sandbox
  PAGERDUTY_PROBE_OUT              default: <work-dir>/probe-run

The raw token is read only from the environment. The script derives the
Authorization header in memory and never writes it to the rendered config,
ID manifest, command line, or probe artifacts.
USAGE
}

case "$COMMAND" in
  discover)
    need_command curl
    need_command jq
    prepare_resources false
    ;;
  author)
    need_command curl
    need_command jq
    [[ "${PAGERDUTY_CONFIRM_TRIAL_ACCOUNT:-}" == "1" ]] || \
      fail \
        "trial_account_confirmation_required" \
        "Set PAGERDUTY_CONFIRM_TRIAL_ACCOUNT=1 for the explicit direct-authoring step."
    prepare_resources true
    ;;
  probe)
    probe
    ;;
  validate)
    validate
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
