# EnvFactory Provider Adapter

## Purpose

Datalox provider runtimes and EnvFactory have complementary boundaries:

- Datalox supplies task-free, resettable provider behavior.
- EnvFactory supplies tool-graph, scenario, task, and trajectory generation.

The adapter compiles an admitted Datalox provider world into the native files
EnvFactory expects. It does not ask EnvFactory's environment generator to
reimplement already-grounded behavior.

```text
admitted provider world
  -> task-free Datalox provider runtime
  -> EnvFactory-native tool + metadata + scenario contract
  -> ToolGraph and QueryGen
```

## Export

```bash
datalox-gate provider export-envfactory \
  --source-world envs/openlmis_supply_chain_v0 \
  --trajectory envs/openlmis_supply_chain_v0/tests/trajectories/openlmis.json \
  --provider-id openlmis \
  --authority openlmis.example \
  --episode-id openlmis-supply-chain-001 \
  --out /tmp/envfactory-openlmis
```

The generated overlay uses EnvFactory's repository layout:

```text
envs/tools/DataloxOpenlmis.py
envs/metadata/DataloxOpenlmis_metadata.json
envs/datalox/DataloxOpenlmis/
configs/mcp_server.fragment.json
patches/envfactory-<commit>.patch
install.py
manifest.json
```

The tool module defines source-inspectable Pydantic classes and
`Scenario_Schema`, which EnvFactory's QueryGen reads directly. The metadata
keeps original response shapes, including top-level arrays and primitives.

Install `datalox-gated-runtime` into EnvFactory's Python environment and run:

```bash
python /tmp/envfactory-openlmis/install.py /path/to/EnvFactory
```

The installer fails closed on the wrong EnvFactory commit, existing files, MCP
name collisions, or an incompatible patch. The v1 adapter is pinned to
EnvFactory commit `eff3b22d3fc26afa14165cfe208c2a4c9ecc39e3` and FastMCP
3.1.0.

## Scenario Lifecycle

EnvFactory generates a small scenario selector rather than an invented copy of
provider state:

```json
{
  "schema_version": "datalox_envfactory_scenario_v1",
  "template_id": "baseline",
  "seed": 0,
  "checkpoint": null
}
```

`load_scenario` materializes the bundled template. After a state change,
`save_scenario` returns the same contract with a complete checkpoint. A later
long-horizon step can reload that checkpoint exactly. Additional reviewed
checkpoints can be exported with repeated
`--scenario-template TEMPLATE_ID=JSON_PATH` arguments.

The adapter deliberately exposes only deterministic, admitted templates. It
does not claim synthetic state diversity that the provider runtime cannot
support.

## Compatibility Patch

Two EnvFactory behaviors at the pinned commit prevent faithful stateful imports:

1. `MCPClientManager` clones stateful stdio clients with `Client.new()`, which
   shares the underlying process in FastMCP 3.1. Concurrent pass@k branches can
   therefore mutate the same server state.
2. ToolGraph parses only object `properties`, dropping root arrays, primitives,
   and unions from dependency construction.

The generated overlay includes a narrow, version-pinned patch. It starts one
stdio process per stateful client and closes that process with the client. It
also represents non-object root outputs without changing provider responses.
The patch belongs upstream eventually; pinning prevents silently applying it to
unknown EnvFactory versions.

## Verified Compatibility

The same exporter is covered across three different provider state machines:

| Provider | Tools | Reference calls |
| --- | ---: | ---: |
| OpenLMIS | 71 | 82 |
| Galaxy | 62 | 109 |
| Opentrons | 19 | 24 |

On 2026-08-11, an OpenLMIS overlay was installed into a clean checkout of the
pinned EnvFactory commit and exercised through EnvFactory's own code:

- `read_scenario_schema(..., mode="Pydantic")` loaded the generated classes;
- all 71 provider tools were agent-visible after lifecycle filtering;
- all 18 non-object root outputs produced ToolGraph parameters;
- four concurrent stateful clients used isolated provider state; and
- a mutated checkpoint survived close, reload, and exact save.

The model-dependent QueryGen text generation was not invoked in this proof.
The integration boundary it consumes - paths, metadata, scenario source,
lifecycle calls, output graph parsing, and pass@k state isolation - was executed
with EnvFactory's pinned dependencies.

## Boundaries

The exporter is provider-independent, but provider grounding is not free. Each
provider still needs truthful behavior, reset state, authorization semantics,
and successful observations for every exported operation.

The provider runtime contains no task, verifier, reward, credential, or live
provider client. EnvFactory or another downstream system owns those layers.
The existing `integrations/envfactory/openlmis_supply_chain_v0` directory is a
consumer-side long-horizon task/verifier example; it is not the generic adapter
or the source of provider behavior.
