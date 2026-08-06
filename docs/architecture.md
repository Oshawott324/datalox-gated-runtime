# Architecture

The first implementation is intentionally small.

```text
CallRequest
  -> GatePolicy.decide()
  -> GatedRuntime.handle()
  -> Ledger.record()
  -> GateResponse
```

## Components

### Call Contract

`CallRequest` captures the agent-visible call: method, path, body, headers, and
optional operation id.

`GateResponse` captures what the agent receives back plus the runtime decision
that produced it.

JSON, text, and null response bodies retain their provider-shaped values.
Exact binary bodies use one reserved, JSON-serializable envelope:

```json
{
  "$datalox_binary_response": {
    "schema_version": "datalox_binary_response_v1",
    "content_type": "image/png",
    "data_base64": "..."
  }
}
```

World code constructs this value with `make_binary_response_body`. The runtime
validates the exact envelope fields, media type, canonical RFC 4648 base64,
response-header consistency, and body-compatible status before recording it.
The envelope stays unchanged in tool results, MCP projections, ledgers, and run
exports. Only the HTTP adapter decodes it to bytes and emits its declared
content type. A malformed reserved envelope is denied with the stable
`binary_response_envelope_invalid` code; it is never recorded as a successful
provider response.

### Policy

`GatePolicy` maps calls to one of:

- `replay`
- `shadow_write`
- `deny`
- `miss`

The default policy is conservative:

- safe reads replay if a response case exists
- unsafe writes shadow-write
- known dangerous operations are denied
- unknown calls are recorded as misses

### Ledger

The ledger records all calls, policy decisions, responses, and shadow mutations.
It is the source of replay and post-run audit evidence.

### Audit

The initial audit is deliberately generic. Domain-specific audits can be layered
on top without changing the call-path runtime.
