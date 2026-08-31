#!/usr/bin/env bash

# Add this array to the project's existing slime launch command. Datalox does
# not replace the model, optimizer, data, rollout, or resource arguments.
: "${SLIME_USER_GENERATE_PATH:?set SLIME_USER_GENERATE_PATH to the consumer-owned custom generator}"
: "${SLIME_USER_REWARD_PATH:?set SLIME_USER_REWARD_PATH to the consumer-owned custom reward}"

SLIME_DATALOX_ARGS=(
  --custom-generate-function-path "${SLIME_USER_GENERATE_PATH}"
  --custom-rm-path "${SLIME_USER_REWARD_PATH}"
  --custom-config-path integrations/slime/custom_config.yaml
  --metadata-key metadata
)
