# PyLabRobot-Backed Hamilton STAR Provider

Hamilton STAR is represented by one deliberately bounded provider pack:

- provider id: `pylabrobot_hamilton_star`;
- source environment: `envs/pylabrobot_hamilton_star_v0`;
- reference system: PyLabRobot `0.2.1` `LiquidHandlerChatterboxBackend`;
- native evaluated-code surface: PyLabRobot `LiquidHandler` methods; and
- grounding boundary: device-free dry-run behavior, not physical Hamilton hardware.

This is a first-class provider pack, not a claim that Datalox reproduces VENUS,
firmware, calibration, motion timing, collisions, or Hamilton liquid classes.

## Complete selected core

The admitted slice contains three complete operation families and nine exposed
operations:

| Family | Reads | Writes |
| --- | --- | --- |
| Lifecycle | handler state | `setup`, `stop` |
| Tip handling | channel and tip-spot state | `pick_up_tips`, `drop_tips` |
| Liquid handling | container and mounted-tip volumes | `aspirate`, `dispense` |

All six writes, repeated-call failures, and the selected invalid-state failures
were executed against the pinned PyLabRobot Chatterbox reference. The local
pack additionally proves atomic batch rejection, read-after-write behavior,
deterministic reset, HTTP/MCP parity, and task-free provider-runtime compilation.

CoRe 96, iSWAP/resource movement, auxiliary instruments, non-STAR backends, and
physical hardware are adjacent capabilities rather than hidden omissions. The
SDK adapter raises an explicit scope error if evaluated code requests them.

## Native SDK call path

PyLabRobot is a Python SDK, not a hosted HTTP API. There is therefore no real
provider URL for the agent to preserve. The consumer's execution boundary
selects `DataloxHamiltonSTARBackend`; evaluated code continues to use normal
PyLabRobot calls:

```python
from pylabrobot.liquid_handling import LiquidHandler

from datalox_gated_runtime.sdk_adapters import DataloxHamiltonSTARBackend

liquid_handler = LiquidHandler(
    backend=DataloxHamiltonSTARBackend(transport),
    deck=my_world_owned_deck,
)

await liquid_handler.setup()
await liquid_handler.pick_up_tips([tip_spot])
await liquid_handler.aspirate([source], vols=[100])
await liquid_handler.dispense([target], vols=[100])
await liquid_handler.return_tips()
await liquid_handler.stop()
```

The agent does not choose a Datalox tool or rewrite those calls. The backend
serializes the world-owned deck state during `setup` and sends standard channel
operations to the isolated provider runtime.

## Gated endpoint and container use

The backend transport uses one reserved, non-routable authority:
`pylabrobot-hamilton-star.invalid`. This is an internal SDK projection, not a
Hamilton endpoint. Compile the provider runtime with that exact authority:

```bash
datalox-gate provider build-runtime \
  --source-world envs/pylabrobot_hamilton_star_v0 \
  --episode-id pylabrobot-hamilton-star-transfer-001 \
  --provider-id pylabrobot_hamilton_star \
  --authority pylabrobot-hamilton-star.invalid \
  --out /tmp/pylabrobot-hamilton-star-provider
```

The ordinary Docker or Kubernetes interception export then maps that authority
to the Datalox sidecar, installs the run CA, and denies external provider
egress. `HamiltonSTARHttpTransport` is constructed with the injected
`httpx.AsyncClient`; if the sidecar is absent, the reserved `.invalid` name
cannot resolve to Hamilton or any public service.

Install the SDK integration explicitly:

```bash
python -m pip install -e '.[hamilton]'
```

The provider runtime remains a task-free gated endpoint. The user's world owns
the deck construction, task, agent, verifier, and reward; Datalox owns only the
mirrored provider state, transitions, failures, reset, and ledger.

## Evidence boundary

The G2 label means local execution of the official open-source PyLabRobot
reference backend. It must not be paraphrased as physical Hamilton validation.
See the pinned [PyLabRobot source](https://github.com/PyLabRobot/pylabrobot/tree/c8c9dcbcf4124ed078f4a8b4b21ec83474d7b7b1)
and the operation-level declaration in `provider_core_coverage.json` for the
exact claim attached to each operation.
