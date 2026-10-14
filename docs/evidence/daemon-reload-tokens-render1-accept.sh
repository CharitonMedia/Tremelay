#!/bin/bash
set -u
D=$1; T=$D/tremelay; V=$D/v.db; cd $D
export XDG_RUNTIME_DIR=$D/run
head -c 24 /dev/urandom | base64 > $D/pass; chmod 600 $D/pass
export TREMELAY_PASSPHRASE="$(cat $D/pass)"
printf '%s' dummy-live-secret > $D/secret
q() { "$@" 2>/dev/null; }
echo "== setup (agent created WITHOUT a token, like a pre-daemon agent)"
$T vault create --path $V >/dev/null 2>&1
CRED=$(q $T credential put --path $V --label demo --type api_key --secret-file $D/secret | tail -1); rm $D/secret
AGENT=$(q $T agent create --path $V --label claude-code | head -1); echo agent=$AGENT
G1=$(q $T grant create --path $V --agent $AGENT --credential $CRED --operation http_broker --resource https://httpbin.org/anything/one --method GET --inject bearer --expires 2027-01-01T00:00:00Z | tail -1)
echo "== daemon"
$T daemon --vault $V --idle-timeout 30m > $D/daemon.out 2>&1 &
DP=$!; sleep 3; cat $D/daemon.out
unset TREMELAY_PASSPHRASE
cat > $D/mcp.json <<J
{"mcpServers":{"tremelay":{"command":"$T","args":["mcp","--daemon","--token-file","$D/cc.token"],"env":{"XDG_RUNTIME_DIR":"$D/run"}}}}
J
cc() { echo "$1" | timeout 300 claude -p --strict-mcp-config --mcp-config $D/mcp.json "--allowedTools=mcp__tremelay__list_capabilities,mcp__tremelay__describe_capability,mcp__tremelay__invoke_capability" 2>&1 | tail -6; }
P="Use the tremelay MCP tools: list_capabilities, then invoke_capability with GET on each active http_broker grant's resource path (path is the URL path, e.g. /anything/one). Reply in at most 4 lines: for each call the resource, the HTTP status, and the Authorization header httpbin echoed. If a call fails, quote the error. Do not guess."
pw() { TREMELAY_PASSPHRASE="$(cat $D/pass)" "$@"; }
echo "== 1. agent made without --token-file: rotate writes its token file (daemon running)"
pw $T agent token rotate --path $V --agent $AGENT --token-file $D/cc.token 2>&1 | tail -1; ls -l $D/cc.token | cut -c1-10
cc "$P"
echo "== 2. grant create while running -> usable"
G2=$(pw $T grant create --path $V --agent $AGENT --credential $CRED --operation http_broker --resource https://httpbin.org/anything/two --method GET --inject bearer --expires 2027-01-01T00:00:00Z 2>/dev/null | tail -1)
cc "$P"
echo "== 3. grant revoke one -> refused/absent"
pw $T grant revoke --path $V --id $G1 >/dev/null 2>&1
cc "$P"
echo "== 4. rotate token at same path; same mcp.json"
cp $D/cc.token $D/old.token
pw $T agent token rotate --path $V --agent $AGENT --token-file $D/cc.token 2>&1 | tail -1
cmp -s $D/cc.token $D/old.token && echo "SAME TOKEN (bad)" || echo "token changed"
cc "$P"
echo "== 5. old token refused"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}'
echo "$INIT" | timeout 10 $T mcp --daemon --token-file $D/old.token; echo "old token exit=$?"
echo "== 6. revoke then issue: same grants"
pw $T agent token revoke --path $V --agent $AGENT 2>&1 | tail -1
echo "$INIT" | timeout 10 $T mcp --daemon --token-file $D/cc.token; echo "revoked token exit=$?"
rm -f $D/cc.token
pw $T agent token issue --path $V --agent $AGENT --token-file $D/cc.token 2>&1 | tail -1
cc "$P"
echo "== daemon still alive (no restart, no passphrase): $(kill -0 $DP 2>/dev/null && echo yes || echo no)"
echo "== 7. CLI commit, then tamper the newest audit row while unlocked -> daemon locks on next call"
pw $T grant create --path $V --agent $AGENT --credential $CRED --operation http_broker --resource https://httpbin.org/anything/three --method GET --inject bearer --expires 2027-01-01T00:00:00Z >/dev/null 2>&1
python3 - "$V" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); cur=c.cursor()
r=cur.execute("select seq,hash from audit order by seq desc limit 1").fetchone()
cur.execute("update audit set hash=? where seq=?",("0"*64,r[0])); c.commit(); print("tampered seq",r[0])
PY
echo "$INIT" | timeout 10 $T mcp --daemon --token-file $D/cc.token; echo "after tamper exit=$?"
sleep 2; echo "daemon alive after tamper: $(kill -0 $DP 2>/dev/null && echo yes || echo no)"; tail -3 $D/daemon.out
kill $DP 2>/dev/null
echo "== audit (pre-tamper rows readable?)"
pw $T audit list --path $V 2>/dev/null | python3 -c 'import sys,json
for l in sys.stdin:
  r=json.loads(l)
  if r["action"].startswith(("agent_token","daemon_auth","grant_")): print(r["seq"],r["action"],r["result"],r.get("agent_id","")[:8])' | tail -20
echo "secret leaked: $(grep -rl dummy-live-secret $D --exclude=tremelay --exclude=run.sh --exclude=out.txt 2>/dev/null | wc -l)"
