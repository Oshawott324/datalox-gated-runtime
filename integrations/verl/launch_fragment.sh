#!/usr/bin/env bash
set -euo pipefail

# Keep the rest of your normal veRL GRPO model, data, actor, resource, reward,
# logging, and checkpoint arguments. These are only the Datalox-related fields.
python3 -m verl.trainer.main_ppo \
  trainer.use_v1=true \
  algorithm.adv_estimator=grpo \
  actor_rollout_ref.rollout.n=8 \
  actor_rollout_ref.rollout.agent.num_workers=8 \
  actor_rollout_ref.rollout.agent.default_agent_loop=datalox_tool_agent \
  actor_rollout_ref.rollout.agent.agent_loop_config_path="$PWD/integrations/verl/agent_loop.yaml" \
  actor_rollout_ref.rollout.multi_turn.enable=true \
  actor_rollout_ref.rollout.multi_turn.tool_config_path=null \
  actor_rollout_ref.rollout.multi_turn.function_tool_path="$PWD/integrations/verl/provider_tools.py" \
  actor_rollout_ref.rollout.multi_turn.format=hermes \
  "$@"
