"""The OIDC-enabled supervisor may run only reviewed immutable actions."""
from pathlib import Path
import re
import unittest


REVIEWED_ACTIONS = {
    'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
    'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
}


def immutable_actions(workflow):
    refs = re.findall(r'^\s*(?:-\s+)?uses:\s+(\S+)', workflow, re.M)
    # Quoted YAML keys are intentionally outside this workflow's canonical
    # format. Count them too so they cannot hide an additional action.
    return (len(re.findall(r'''(?:\buses|["']uses["'])\s*:''', workflow)) == len(refs)
            and len(refs) == len(REVIEWED_ACTIONS)
            and set(refs) == REVIEWED_ACTIONS
            and all(re.fullmatch(r'actions/[a-z-]+@[0-9a-f]{40}', ref)
                    for ref in refs))


class SupervisorActionPins(unittest.TestCase):
    def test_privileged_workflow_uses_only_reviewed_full_action_shas(self):
        path = Path(__file__).resolve().parents[1] / '.github/workflows/checkpoint-supervisor.yml'
        workflow = path.read_text()
        self.assertIn('id-token: write', workflow)
        self.assertTrue(immutable_actions(workflow))

    def test_tags_abbreviated_shas_new_actions_and_inline_uses_are_rejected(self):
        good = '\n'.join('- uses: ' + ref for ref in sorted(REVIEWED_ACTIONS))
        self.assertTrue(immutable_actions(good))
        sha = '11d5960a326750d5838078e36cf38b85af677262'
        for replacement in ['v4', 'main', sha[:10], 'f' * 40]:
            with self.subTest(replacement=replacement):
                self.assertFalse(immutable_actions(good.replace(sha, replacement)))
        self.assertFalse(immutable_actions(good + '\n- uses: other/action@' + 'a' * 40))
        self.assertFalse(immutable_actions(good + '\n- {uses: other/action@v1}'))
        self.assertFalse(immutable_actions(good + '\n- "uses": other/action@v1'))
        self.assertFalse(immutable_actions(good + "\n- {'uses': other/action@v1}"))


if __name__ == '__main__':
    unittest.main()
