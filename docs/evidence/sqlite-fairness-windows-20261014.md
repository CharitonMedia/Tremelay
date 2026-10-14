# V1 item 3f: 20 consecutive windows-latest runs, 2026-10-14

Commit under test: bfdd22c (branch `v1-3f-sqlite-fair`, PR #81). The `test (windows-latest)` job of the CI workflow runs `go test ./...`, which includes TestSessionReloadUnderConcurrentCalls, TestSSHUserAuthInterop, TestMCPNetworkBrokerRejectsRetargeting and TestTamperAndSwap. Runs: the PR run (two attempts), the branch push run, and push runs of 19 throwaway branches `tmp-3f-win-01..19` pointing at the same commit (deleted afterwards). Every windows-latest job on that commit is listed; none failed.

```
run_id attempt status conclusion
38565652058 1 completed success
38565659095 1 completed success
38565659095 2 completed success
38567462675 1 completed success
38567467020 1 completed success
38567468867 1 completed success
38567472841 1 completed success
38567476828 1 completed success
38567478090 1 completed success
38567481573 1 completed success
38567484300 1 completed success
38567487449 1 completed success
38567490879 1 completed success
38567494123 1 completed success
38567498043 1 completed success
38567500178 1 completed success
38567504025 1 completed success
38567506971 1 completed success
38567511004 1 completed success
38567513675 1 completed success
38567520159 1 completed success
38567521743 1 completed success
```

Total: 22 of 22 succeeded. For comparison, the same job failed on TestSessionReloadUnderConcurrentCalls (ErrIO) on #68's head earlier the same day.
