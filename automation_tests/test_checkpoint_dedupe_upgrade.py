import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
HEAD="a"*40

class CheckpointDedupeUpgrade(unittest.TestCase):
    def run_dedupe(self, comments):
        workflow=(ROOT/".github/workflows/goal.yml").read_text()
        start=workflow.index('existing=$(HEAD="$head" LIMIT="$max_cycles" python - <<\'PY\'')
        script=workflow[start:].split("\n",1)[1].split("\n          PY",1)[0]
        script="\n".join(line[10:] for line in script.splitlines())
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"scripts").symlink_to(ROOT/"scripts",target_is_directory=True)
            (root/"cycle_comments.json").write_text(json.dumps([comments]))
            env=dict(os.environ,HEAD=HEAD,LIMIT="3")
            result=subprocess.run([sys.executable,"-c",script],cwd=root,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            return result.stdout.strip()

    def body(self, head=HEAD, evidence=""):
        return ("Automation stopped after 3 counted attempts in this segment (limit 3).\n"
                "A documented independent supervisor assessment is required before more implementation.\n"
                f"Latest head: `{head}`.\n\n{evidence}\n\n"
                f"<!-- tremelay-cycle-stop head:{head} limit:3 -->")

    def test_real_stop_owners_deduplicate(self):
        for owner in ["pattalkslaw-del","github-actions[bot]"]:
            self.assertEqual(self.run_dedupe([{"user":{"login":owner},"body":self.body()}]),"yes")

    def test_untrusted_or_quoted_marker_cannot_hide_checkpoint(self):
        marker=f"<!-- tremelay-cycle-stop head:{HEAD} limit:3 -->"
        cases=[
            {"user":{"login":"attacker"},"body":self.body()},
            {"user":{"login":"pattalkslaw-del"},"body":"Quoted example:\n"+marker},
            {"user":{"login":"pattalkslaw-del"},"body":self.body("b"*40,marker)},
            {"user":{"login":"github-actions[bot]"},"body":self.body().replace("limit:3","limit:9")},
        ]
        for comment in cases:
            with self.subTest(comment=comment):
                self.assertEqual(self.run_dedupe([comment]),"no")

if __name__=="__main__":
    unittest.main()
