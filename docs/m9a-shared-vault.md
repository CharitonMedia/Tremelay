# M9a — local shared-vault authorization reference

This is a partial slice of M9. A host-asserted member requests one exact `local_artifact_attest` grant. A different active owner approves that stored request. The designated agent obtains a verifiable Ed25519 attestation through the existing broker and does not receive the private key. Revocation, expiry, or membership removal stops later signatures. A signature already returned is not recalled.

This is not authentication, enrollment, recovery, independent custody, or production shared access. The process and the vault passphrase remain the custody authority. Two synthetic identities do not establish two real people. There is no `--human-id` flag and no shared-mode plaintext retrieval.

The encrypted document binds one vault to one organization and stores memberships, generations, requests, and grant provenance. Legacy single-user vaults stay single-user. An older reader fails closed on a shared document because strict decoding rejects the new fields. See [ADR 0015](adr/0015-local-shared-vault-authorization.md).

## Local demonstration

The demonstration uses a temporary database, a disposable Ed25519 key, synthetic identities, the session clock, and an in-memory notifier. It does not call a network.

```bash
go test ./internal/vault/ -run 'TestSharedSyntheticDemo' -count=1
```

`TestSharedSyntheticDemo` is the acceptance path: Bob cannot approve his own request, Alice approves the original scope, the agent verifies an attestation, the same grant works after reopen, and revocation denies the next signature.

The rest of the M9a evidence is the other `TestShared*` tests in `internal/vault/shared_test.go`: direct-issue and retrieval denials, single-user preservation, organization isolation, one-grant approval, generation invalidation, stale sessions, fault rollback, tamper and old-reader rejection, document writers, and sentinel and reentry checks.

## What was not run

No live service, external notification, or production migration was exercised. The prohibited M7 HTTP transport disclosure runtime probe is not part of these tests and was not run.
