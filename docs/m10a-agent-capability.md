# M10a — bound local agent capability interface

This is a partial slice of M10. A trusted host binds one `AgentPrincipal` to an in-process adapter. The client lists, describes, and invokes that principal's `local_artifact_attest` grants by sending one versioned message to `Exchange`. Each handle names one exact grant, credential, key identity, and resource. Invocation does not move an old handle onto a newer grant or key. `request_capability` is rejected and does not create a request, a grant, or a human assertion.

This is not a public SDK, a socket, a network listener, or a demonstrated MCP transport. It does not authenticate the agent. The host that unlocked the vault remains the custody boundary. M9 is also not complete. See [ADR 0017](adr/0017-agent-capability-interface.md).

The message is one object: version `1`, a method byte, a field count, and length-prefixed fields. Duplicate fields, unknown fields, trailing bytes, and input above `MaxAgentCapMessage` fail closed. The attestation payload limit remains 64 KiB and is not truncated. Error responses use a fixed code and a fixed message. A locked session, a stale session, or a failed audit returns no response and is not a claim that an event was stored.

A catalog entry shows the handle, `local_artifact_attest`, the resource, the public key id, a lifecycle status, and the expiry. It does not show credential labels, human identities, or HTTP or SSH grants. The status is advisory. The invoke path checks the selected grant again, including shared membership generations.

## Local demonstration

The demonstration uses a temporary database, a disposable Ed25519 key, synthetic identities, and the in-process adapter. It does not call a network.

```bash
go test ./internal/vault/ -run 'TestAgentCapSyntheticDemo' -count=1
```

`TestAgentCapSyntheticDemo` approves one shared local-attestation grant, then discovers, describes, and invokes it only through the adapter and verifies the signature. The other `TestAgentCap*` tests cover isolation, foreign handles, schema failures, revocation, expiry, suspension, key replacement, membership invalidation, stale sessions, audit failures, and two matching grants.

## What was not run

No live service, MCP peer, remote agent, or production credential was used. The historical standalone validation probes and the old M7 network probe were not run. Existing callback and reentry tests remain the coverage for those host paths. The new exact-grant check is the adapter test that revokes the selected grant during the signing callback while another matching grant exists.
