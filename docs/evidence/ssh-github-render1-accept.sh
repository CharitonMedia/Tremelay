#!/bin/bash
# 5b live acceptance on render-1. Throwaway tmpfs vault; deploy key removed at the end.
set -u
WT=/home/patrick/.hermes/workspaces/tremelay-wt/v1-ssh-github
D=$(mktemp -d /dev/shm/trem5b.XXXXXX); chmod 700 "$D"
export XDG_RUNTIME_DIR=$D/run; mkdir -m700 "$XDG_RUNTIME_DIR"
RH=$HOME; export HOME=$D/home; mkdir -p "$HOME"
T="$D/tremelay"; V="$D/vault.db"
(cd "$WT" && go build -o "$T" ./cmd/tremelay) || exit 1
echo "commit under test: $(git -C "$WT" rev-parse --short HEAD)"
head -c 24 /dev/urandom | base64 > "$D/pp"; chmod 600 "$D/pp"
P() { TREMELAY_PASSPHRASE=$(cat "$D/pp") "$T" "$@"; }
P vault create --path "$V" >/dev/null || exit 1
openssl genpkey -algorithm ed25519 -outform DER -out "$D/k.der" 2>/dev/null
CRED=$(P credential put --path "$V" --label "gh deploy" --type ed25519 --secret-file "$D/k.der" 2>/dev/null | head -1)
shred -u "$D/k.der"
AG=$(P agent create --path "$V" --label agent5b --token-file "$D/a.token" 2>/dev/null | head -1)
echo "cred=$CRED agent=$AG"; [ -n "$CRED" ] && [ -n "$AG" ] || exit 1
curl -fsS https://api.github.com/meta | python3 -c 'import json,sys; print([k for k in json.load(sys.stdin)["ssh_keys"] if k.startswith("ssh-ed25519")][0])' > "$D/github.pub"
FP=$(ssh-keygen -lf "$D/github.pub" | awk '{print $2}'); echo "api.github.com/meta ed25519 fp: $FP"
[ "$FP" = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU" ] || { echo "FP MISMATCH, stop"; exit 1; }
HK=$(awk '{print $2}' "$D/github.pub" | base64 -d | xxd -p -c 0)
echo "github.com $(cat "$D/github.pub")" > "$D/kh"
G1=$(P grant create --path "$V" --agent "$AG" --credential "$CRED" --operation ssh_userauth --resource "github tremelay-ssh-test push" --ssh-user git --ssh-host-key "$HK" --expires 2026-10-15T00:00:00Z 2>/dev/null | head -1)
echo "grant1=$G1"; [ -n "$G1" ] || exit 1
KEY_ID=$(P capability list --path "$V" --agent "$AG" 2>/dev/null | grep ssh_userauth | sed 's/.*"key_id":"\([0-9a-f]*\)".*/\1/')
PUB="ssh-ed25519 $({ printf '\0\0\0\vssh-ed25519\0\0\0\040'; printf %s "$KEY_ID" | xxd -r -p; } | base64 -w0)"
DK=$(HOME=$RH gh api -X POST repos/CharitonMedia/tremelay-ssh-test/keys -f title="tremelay-5b-$(date +%s)" -f key="$PUB" -F read_only=false --jq .id) || exit 1
echo "deploy key added id=$DK"
cleanup() { kill $SA $DM 2>/dev/null; HOME=$RH gh api -X DELETE repos/CharitonMedia/tremelay-ssh-test/keys/$DK && echo "deploy key $DK deleted"; rm -rf "${D:?}"; }
trap cleanup EXIT
TREMELAY_PASSPHRASE=$(cat "$D/pp") "$T" daemon --vault "$V" --idle-timeout 1h > "$D/daemon.log" 2>&1 & DM=$!
sleep 3
"$T" ssh-agent --token-file "$D/a.token" --socket "$XDG_RUNTIME_DIR/sa.sock" > "$D/sa.log" 2>&1 & SA=$!
sleep 2
export GIT_SSH_COMMAND="ssh -F /dev/null -o IdentityFile=none -o IdentityAgent=$XDG_RUNTIME_DIR/sa.sock -o UserKnownHostsFile=$D/kh -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o BatchMode=yes"
export GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=tremelay-5b GIT_AUTHOR_EMAIL=t@invalid GIT_COMMITTER_NAME=tremelay-5b GIT_COMMITTER_EMAIL=t@invalid
echo "== 1. clone + push with pinned github.com key"
git clone -q git@github.com:CharitonMedia/tremelay-ssh-test.git "$D/repo" && cd "$D/repo" && echo "5b $(date -u +%FT%TZ)" >> tremelay-5b.txt && git add . && git commit -qm "5b live push via tremelay ssh-agent" && git push -q origin HEAD 2>&1; echo "push exit=$?"; git log --oneline -1
echo "== 2. revoke grant1, push again"
P grant revoke --path "$V" --id "$G1" >/dev/null 2>&1; sleep 1
echo "x" >> tremelay-5b.txt; git commit -qam "should not land"; git push origin HEAD 2>&1 | tail -2; echo "push exit=${PIPESTATUS[0]}"
echo "== 3. grant with a different host key, push"
ssh-keygen -q -t ed25519 -N "" -f "$D/other"
OHK=$(awk '{print $2}' "$D/other.pub" | base64 -d | xxd -p -c 0)
P grant create --path "$V" --agent "$AG" --credential "$CRED" --operation ssh_userauth --resource "wrong host key" --ssh-user git --ssh-host-key "$OHK" --expires 2026-10-15T00:00:00Z 2>/dev/null | head -1
sleep 1; git push origin HEAD 2>&1 | tail -2; echo "push exit=${PIPESTATUS[0]}"
echo "== remote state"; git ls-remote origin HEAD; git rev-parse HEAD~1
echo "== audit ssh_userauth"
P audit list --path "$V" --action ssh_userauth 2>&1 | sed -E 's/"(hash|prev_hash)":"[0-9a-f]+"/"\1":"…"/g' | tail -20
echo "== secret leak check"; grep -c "PRIVATE" "$D/daemon.log" "$D/sa.log"
