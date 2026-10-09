"""Offline process-boundary tests. Never invoke the real provider helper."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import checkpoint_supervisor as s

HEAD = 'a' * 40
DECISION = {'decision': 'resume', 'head': HEAD, 'assessment': 'A bounded correction is available.',
            'correction': 'Repair the index and add rollback regression tests.', 'reason_for_user': ''}
USAGE = {'input_tokens': 100, 'output_tokens': 50}
ENVELOPE = {'status': 'finished', 'model': s.MODEL, 'result': json.dumps(DECISION), 'usage': USAGE}
SMOKE = {'smoke_succeeded': True, 'model_called': True, 'model': s.MODEL,
         'usage': {'input_tokens': 42, 'output_tokens': 8}}
PREFLIGHT = {'authentication_succeeded': True, 'scope': 'workspace:developer',
             'expires_in': 3600, 'model_called': False}
ENV = {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main',
       'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://oidc.example.invalid/request',
       'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'test-only-oidc-67a4dddc09b44e16b9ebe7c98dac5f2a',
       'GH_TOKEN': 'test-only-github-9f5087c46bb44f4681e53584b01f8816',
       'CURSOR_API_KEY': 'test-only-cursor-724ac2e3ec2a4ba6934b3998b7f549ef',
       'OPENAI_API_KEY': 'test-only-openai-dcb211fc42d94c6180b1fc72f0fcc451',
       'ANTHROPIC_API_KEY': 'test-only-anthropic-d50e9d3b925a44329cafc80d5b18a21d'}


@unittest.skipUnless(os.name == 'posix', 'The assessor intentionally requires POSIX')
class AssessorBoundary(unittest.TestCase):
    @contextlib.contextmanager
    def helper(self, source, *, environment=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fake_assessor.py'
            path.write_text(textwrap.dedent(source))
            with patch.object(s, 'ASSESSOR_PATH', path), patch.dict(os.environ, environment or ENV, clear=True), \
                    patch.object(s.urllib.request, 'build_opener') as http:
                yield path, http
                http.assert_not_called()  # No parent-side API or provider fallback.

    @staticmethod
    def output_source(text, *, returncode=0):
        return ('import sys\n'
                'sys.stdin.buffer.read()\n'
                f'sys.stdout.buffer.write({text!r})\n'
                'sys.stdout.buffer.flush()\n'
                f'sys.exit({returncode})\n')

    def assess_output(self, text):
        with self.helper(self.output_source(text)):
            return s.assess({'head': HEAD})

    def test_exact_contract_and_credential_minimal_fresh_process(self):
        evidence = {'head': HEAD, 'sources': {'untrusted.py': 'raise RuntimeError("never execute")'}}
        payload = {'model': s.MODEL, 'head': HEAD, 'instructions': s.INSTRUCTIONS,
                   'schema': s.SCHEMA, 'evidence': evidence}
        source = f'''
            import json, os, sys
            assert sys.flags.isolated and sys.flags.dont_write_bytecode
            assert json.load(sys.stdin) == {payload!r}
            assert os.listdir(os.getcwd()) == []
            assert os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN'] == {ENV['ACTIONS_ID_TOKEN_REQUEST_TOKEN']!r}
            print({json.dumps(ENVELOPE)!r})
        '''
        ambient = dict(ENV, PATH='/untrusted/bin', HOME='/untrusted/home',
            PYTHONPATH='/untrusted/python', PYTHONSTARTUP='/untrusted/startup',
            HTTP_PROXY='https://attacker.invalid', HTTPS_PROXY='https://attacker.invalid',
            ALL_PROXY='https://attacker.invalid', ANTHROPIC_BASE_URL='https://attacker.invalid',
            OPENAI_BASE_URL='https://attacker.invalid', CURSOR_CONFIG_DIR='/untrusted/config',
            NODE_OPTIONS='--require=/untrusted/code')
        original_popen = subprocess.Popen
        starts = []
        directories = []
        def start(args, **kwargs):
            starts.append(args)
            self.assertEqual(args[:3], [str(Path(sys.executable).resolve()), '-I', '-B'])
            self.assertTrue(Path(args[3]).is_absolute())
            env = kwargs['env']
            allowed = {'PATH', 'LANG', 'HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
                       'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR',
                       'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'}
            self.assertEqual(set(env), allowed)
            self.assertEqual(env['PATH'], '/usr/local/bin:/usr/bin:/bin')
            self.assertEqual(env['LANG'], 'C.UTF-8')
            self.assertTrue(kwargs['start_new_session'])
            self.assertTrue(kwargs['close_fds'])
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stdin'], subprocess.PIPE)
            self.assertTrue(hasattr(kwargs['stdout'], 'fileno'))
            paths = [kwargs['cwd']] + [Path(env[k]) for k in allowed if k == 'HOME' or k.startswith('XDG_')]
            self.assertEqual(len(set(paths)), len(paths))
            for path in paths:
                self.assertEqual(list(path.iterdir()), [])
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            directories.extend(paths)
            return original_popen(args, **kwargs)
        with self.helper(source, environment=ambient), patch.object(s.subprocess, 'Popen', side_effect=start):
            self.assertEqual(s.assess(evidence), (DECISION, USAGE))
            self.assertEqual(s.assess(evidence), (DECISION, USAGE))
        self.assertEqual(len(starts), 2)
        self.assertEqual(len(set(directories)), len(directories))
        self.assertTrue(all(not path.exists() for path in directories))

    def test_production_helper_is_pinned_to_trusted_script_directory(self):
        self.assertEqual(s.ASSESSOR_PATH, Path(s.__file__).resolve().with_name('anthropic_checkpoint_assessor.py'))
        self.assertEqual(s.ASSESSOR_TIMEOUT_SECONDS, 240)
        self.assertEqual(s.MAX_ASSESSOR_OUTPUT_BYTES, 96 * 1024)

    def test_malformed_partial_multiple_nonfinite_and_duplicate_envelopes_fail_closed(self):
        raw = json.dumps(ENVELOPE)
        bad = [b'', b'{', b'not-json', b'\xff', raw.encode() + b'\n{}', b'[]', b'null',
               b'NaN', b'Infinity', b'-Infinity',
               raw.replace('"finished"', '"finished", "status": "finished"').encode(),
               raw.replace('"input_tokens": 100', '"input_tokens": NaN').encode(),
               raw.replace('"input_tokens": 100', '"input_tokens": 100, "input_tokens": 100').encode()]
        for content in bad:
            with self.subTest(content=content[:80]), self.assertRaises(s.Stop):
                self.assess_output(content)

    def test_envelope_status_model_keys_and_usage_are_strict(self):
        bad = [dict(ENVELOPE, status=value) for value in ['incomplete', 'error', 'cancelled', 'running', None]]
        bad += [dict(ENVELOPE, model='gpt-6.1-sol'), dict(ENVELOPE, model='claude-other'),
                dict(ENVELOPE, endpoint='https://attacker.invalid'), dict(ENVELOPE, result=DECISION),
                {k: v for k, v in ENVELOPE.items() if k != 'usage'}]
        for usage in [{}, [], {'input_tokens': 1}, dict(USAGE, extra=1),
                      *[dict(USAGE, input_tokens=v) for v in [-1, True, 1.5, '100', 2 ** 53]]]:
            bad.append(dict(ENVELOPE, usage=usage))
        for envelope in bad:
            with self.subTest(envelope=envelope), self.assertRaises(s.Stop):
                self.assess_output(json.dumps(envelope).encode())
        self.assertEqual(self.assess_output(json.dumps(dict(ENVELOPE, usage=dict.fromkeys(USAGE, 0))).encode())[1],
                         dict.fromkeys(USAGE, 0))

    def test_decision_exact_head_schema_and_json_cannot_be_bypassed(self):
        bad = [dict(DECISION, head='b' * 40), dict(DECISION, decision='merge'),
               dict(DECISION, tool='shell'), dict(DECISION, correction=''),
               dict(DECISION, assessment='<!-- tremelay-human-resume -->'),
               dict(DECISION, correction='@codex review'), dict(DECISION, reason_for_user='approve')]
        texts = [json.dumps(value) for value in bad]
        texts += ['null', '{}{}', json.dumps(DECISION).replace('"resume"', '"resume", "decision": "resume"'),
                  json.dumps(DECISION).replace('"reason_for_user": ""', '"reason_for_user": NaN')]
        for text in texts:
            with self.subTest(result=text), self.assertRaises(s.Stop):
                self.assess_output(json.dumps(dict(ENVELOPE, result=text)).encode())

    def test_evidence_request_and_output_limits_fail_before_unbounded_read(self):
        with patch.object(s, 'invoke_assessor') as helper:
            for evidence in [{'head': HEAD, 'body': 'x' * s.MAX_BYTES},
                             {'head': HEAD, 'body': float('nan')}, {'head': 'bad'}]:
                with self.assertRaises(s.Stop):
                    s.assess(evidence)
            helper.assert_not_called()
        with patch.dict(os.environ, ENV, clear=True), patch.object(s.subprocess, 'Popen') as child:
            with self.assertRaises(s.Stop):
                s.invoke_assessor({'body': 'x' * s.MAX_ASSESSOR_REQUEST_BYTES})
            child.assert_not_called()
        with self.assertRaisesRegex(s.Stop, 'output exceeds its bound'):
            self.assess_output(b'x' * (s.MAX_ASSESSOR_OUTPUT_BYTES + 1))

    def test_nonzero_exit_and_os_errors_cannot_leak_tokens_or_retry(self):
        token = ENV['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
        source = f'import sys\nsys.stdin.read()\nprint({token!r})\nprint({token!r}, file=sys.stderr)\nsys.exit(1)\n'
        stdout, stderr = io.StringIO(), io.StringIO()
        with self.helper(source), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(s.Stop) as error:
                s.assess({'head': HEAD})
        self.assertNotIn(token, str(error.exception) + stdout.getvalue() + stderr.getvalue())
        self.assertIsNone(error.exception.__cause__)
        with patch.dict(os.environ, ENV, clear=True), patch.object(s.subprocess, 'Popen', side_effect=OSError(token)) as child, \
                patch.object(s.urllib.request, 'build_opener') as fallback:
            with self.assertRaises(s.Stop) as error:
                s.assess({'head': HEAD})
            self.assertNotIn(token, str(error.exception))
            child.assert_called_once()
            fallback.assert_not_called()

    def test_only_exact_main_workflow_can_request_identity(self):
        for change in [{'GITHUB_REPOSITORY': 'other/repo'}, {'GITHUB_REF': 'refs/heads/feature'},
                       {'GITHUB_WORKFLOW_REF': ENV['GITHUB_WORKFLOW_REF'].replace('@refs/heads/main', '@refs/heads/feature')},
                       {'GITHUB_WORKFLOW_REF': ENV['GITHUB_WORKFLOW_REF'].replace('checkpoint-supervisor.yml', 'other.yml')},
                       {'ACTIONS_ID_TOKEN_REQUEST_URL': ''}, {'ACTIONS_ID_TOKEN_REQUEST_TOKEN': ''}]:
            with self.subTest(change=change), patch.dict(os.environ, dict(ENV, **change), clear=True), \
                    patch.object(s.subprocess, 'Popen') as child:
                for preflight in [False, True]:
                    with self.assertRaises(s.Stop):
                        s.invoke_assessor({}, preflight=preflight)
                child.assert_not_called()
        with patch.dict(os.environ, ENV, clear=True), patch.object(s.os, 'name', 'nt'), \
                patch.object(s.subprocess, 'Popen') as child:
            with self.assertRaisesRegex(s.Stop, 'requires POSIX'):
                s.invoke_assessor({})
            child.assert_not_called()

    def test_authentication_preflight_has_no_model_input_and_strict_result(self):
        source = f'''
            import sys
            assert sys.argv[1:] == ['--preflight']
            assert sys.stdin.buffer.read() == b''
            print({json.dumps(PREFLIGHT)!r})
        '''
        with self.helper(source):
            self.assertEqual(s.authentication_preflight(), PREFLIGHT)
        for result in [dict(PREFLIGHT, authentication_succeeded=False), dict(PREFLIGHT, scope='other'),
                       dict(PREFLIGHT, model_called=True), dict(PREFLIGHT, expires_in=True),
                       dict(PREFLIGHT, expires_in=0), dict(PREFLIGHT, token='must-not-return-token')]:
            with patch.object(s, 'invoke_assessor', return_value=result) as helper, self.assertRaises(s.Stop):
                s.authentication_preflight()
            helper.assert_called_once_with(preflight=True)

    def test_model_smoke_uses_empty_input_and_only_diagnostic_flag(self):
        source = f'''
            import sys
            assert sys.argv[1:] == ['--smoke']
            assert sys.stdin.buffer.read() == b''
            print({json.dumps(SMOKE)!r})
        '''
        with self.helper(source):
            self.assertEqual(s.model_smoke(), SMOKE)
        with patch.object(s, 'invoke_assessor', return_value=SMOKE) as helper:
            self.assertEqual(s.model_smoke(), SMOKE)
            helper.assert_called_once_with(smoke=True)

    def test_model_smoke_result_requires_exact_model_flags_keys_and_small_usage(self):
        bad = [dict(SMOKE, model='gpt-6.1-sol'), dict(SMOKE, smoke_succeeded=False),
               dict(SMOKE, model_called=False), dict(SMOKE, result=json.dumps(DECISION)),
               dict(SMOKE, usage={}), dict(SMOKE, usage=dict(USAGE, extra=1))]
        bad += [dict(SMOKE, usage=dict(USAGE, output_tokens=value))
                for value in [0, -1, 257, True, 1.5, '8', 2 ** 53, float('nan')]]
        bad += [dict(SMOKE, usage=dict(USAGE, input_tokens=value))
                for value in [-1, True, '42', 2 ** 53]]
        for result in bad:
            with self.subTest(result=result), patch.object(s, 'invoke_assessor', return_value=result), \
                    self.assertRaises(s.Stop):
                s.model_smoke()
        with patch.object(s, 'invoke_assessor', return_value=dict(SMOKE, usage={'input_tokens': 0, 'output_tokens': 256})):
            self.assertEqual(s.model_smoke()['usage']['output_tokens'], 256)

    def test_diagnostic_modes_reject_assessment_payload_or_each_other_before_calls(self):
        for payload, flags in [(None, {'preflight': True, 'smoke': True}),
                               ({'head': HEAD}, {'smoke': True}),
                               ({'head': HEAD}, {'preflight': True})]:
            with patch.object(s, 'assessor_context_guard') as guard, patch.object(s.subprocess, 'Popen') as child:
                with self.assertRaises(s.Stop):
                    s.invoke_assessor(payload, **flags)
                guard.assert_not_called()
                child.assert_not_called()
        with patch.object(sys, 'argv', ['supervisor', '--preflight', '--model-smoke']), \
                patch.object(s, 'gh') as github, patch.object(s, 'invoke_assessor') as helper, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                s.main()
            self.assertEqual(error.exception.code, 2)
            github.assert_not_called()
            helper.assert_not_called()

    def test_manual_model_smoke_works_before_activation_without_checkpoint_or_worker(self):
        env = {name: value for name, value in ENV.items() if name not in {'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'}}
        for activation in ['', 'reviewed-v1-d9cfdd332b6a490e9999f037f632a750', s.ACTIVATION_VALUE]:
            with patch.dict(os.environ, dict(env, TREMELAY_SUPERVISOR_ACTIVATION=activation), clear=True), \
                    patch.object(sys, 'argv', ['supervisor', '--model-smoke']), \
                    patch.object(s, 'gh', return_value={'login': s.AUTHOR}) as github, \
                    patch.object(s, 'invoke_assessor', return_value=SMOKE) as helper, \
                    patch.object(s, 'authentication_preflight') as auth, patch.object(s, 'assess') as assess, \
                    patch.object(s, 'pages') as pages, patch.object(s, 'run_one') as run_one, \
                    patch.object(s, 'cursor') as worker, contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(s.main(), 0)
                github.assert_called_once_with('user')
                helper.assert_called_once_with(smoke=True)
                auth.assert_not_called()
                assess.assert_not_called()
                pages.assert_not_called()
                run_one.assert_not_called()
                worker.assert_not_called()
                self.assertIn(s.MODEL, output.getvalue())
                self.assertIn('input tokens 42, output tokens 8', output.getvalue())
                for value in ENV.values():
                    self.assertNotIn(value, output.getvalue())
                self.assertNotIn(s.MARKER, output.getvalue())

    def test_failed_smoke_is_not_retried_and_cannot_fall_through_to_assessment(self):
        with patch.dict(os.environ, ENV, clear=True), patch.object(sys, 'argv', ['supervisor', '--model-smoke']), \
                patch.object(s, 'gh', return_value={'login': s.AUTHOR}) as github, \
                patch.object(s, 'invoke_assessor', side_effect=s.Stop('Ambiguous smoke result')) as helper, \
                patch.object(s, 'pages') as pages, patch.object(s, 'assess') as assess, \
                patch.object(s, 'cursor') as worker:
            with self.assertRaises(s.Stop):
                s.main()
            github.assert_called_once_with('user')
            helper.assert_called_once_with(smoke=True)
            pages.assert_not_called()
            assess.assert_not_called()
            worker.assert_not_called()

    def test_main_preflight_checks_owner_and_cursor_before_auth_only(self):
        env = {k: v for k, v in ENV.items() if k not in {'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'}}
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['supervisor', '--preflight']), \
                patch.object(s, 'gh', return_value={'login': s.AUTHOR}) as github, \
                patch.object(s, 'authentication_preflight', return_value=PREFLIGHT) as auth, \
                patch.object(s, 'assess') as model, patch.object(s, 'cursor') as worker:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(s.main(), 0)
            github.assert_called_once_with('user')
            auth.assert_called_once_with()
            model.assert_not_called()
            worker.assert_not_called()
            for value in ENV.values():
                self.assertNotIn(value, output.getvalue())
        for change in [{'CURSOR_API_KEY': ''}, {'GH_TOKEN': ''}]:
            with patch.dict(os.environ, dict(env, **change), clear=True), \
                    patch.object(sys, 'argv', ['supervisor', '--preflight']), \
                    patch.object(s, 'authentication_preflight') as auth, self.assertRaises(s.Stop):
                s.main()
            auth.assert_not_called()
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['supervisor', '--preflight']), \
                patch.object(s, 'gh', return_value={'login': 'outsider'}), \
                patch.object(s, 'authentication_preflight') as auth, self.assertRaises(s.Stop):
            s.main()
        auth.assert_not_called()

    def test_main_requires_trusted_workflow_before_recovery_or_preflight(self):
        for mode in [[], ['--preflight'], ['--model-smoke']]:
            for change in [{'GITHUB_REF': 'refs/heads/feature'}, {'GITHUB_WORKFLOW_REF': 'other/workflow'}]:
                env = dict(ENV, TREMELAY_SUPERVISOR_ACTIVATION=s.ACTIVATION_VALUE, **change)
                with patch.dict(os.environ, env, clear=True), \
                        patch.object(sys, 'argv', ['supervisor'] + mode), \
                        patch.object(s, 'gh') as github, patch.object(s, 'pages') as pages, \
                        patch.object(s, 'invoke_assessor') as helper, patch.object(s, 'cursor') as worker:
                    with self.assertRaisesRegex(s.Stop, 'requires the trusted main workflow'):
                        s.main()
                    github.assert_not_called()
                    pages.assert_not_called()
                    helper.assert_not_called()
                    worker.assert_not_called()

    def test_recovery_needs_no_new_identity_or_static_model_key(self):
        env = {name: value for name, value in ENV.items()
               if not name.startswith('ACTIONS_') and name not in {'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'}}
        env['TREMELAY_SUPERVISOR_ACTIVATION'] = s.ACTIVATION_VALUE
        pull = {'number': 11}
        comment, state = {'id': 100}, {'phase': 'working'}
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                patch.object(s, 'gh', return_value={'login': s.AUTHOR}), \
                patch.object(s, 'pages', side_effect=[[pull], []]), patch.object(s, 'eligible', return_value=True), \
                patch.object(s, 'records', return_value=[(comment, state)]), \
                patch.object(s, 'recover_worker') as recovery, patch.object(s, 'invoke_assessor') as helper:
            self.assertEqual(s.main(), 0)
            recovery.assert_called_once_with(pull, comment, state)
            helper.assert_not_called()

    def test_cancellation_ends_scan_before_assessing_another_pr(self):
        env = dict(ENV, TREMELAY_SUPERVISOR_ACTIVATION=s.ACTIVATION_VALUE)
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                patch.object(s, 'gh', return_value={'login': s.AUTHOR}), \
                patch.object(s, 'pages', side_effect=[[{'number': 11}, {'number': 12}], []]), \
                patch.object(s, 'eligible', return_value=True), patch.object(s, 'records', return_value=[]), \
                patch.object(s, 'run_one', side_effect=s.AssessmentCancelled('Cancelled')) as assess:
            with self.assertRaises(s.AssessmentCancelled):
                s.main()
            assess.assert_called_once_with({'number': 11}, 3)

    def test_prior_activation_values_do_not_request_identity_or_make_calls(self):
        for activation in ['', 'true', 'reviewed-v1-d9cfdd332b6a490e9999f037f632a750',
                           'cursor-v2-43b97c8db2a048cba47178df2e964a2f']:
            env = dict(ENV, TREMELAY_SUPERVISOR_ACTIVATION=activation)
            with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                    patch.object(s, 'gh') as github, patch.object(s, 'invoke_assessor') as helper, \
                    patch.object(s, 'cursor') as worker, patch.object(s, 'model_smoke') as smoke, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(s.main(), 0)
                github.assert_not_called()
                helper.assert_not_called()
                worker.assert_not_called()
                smoke.assert_not_called()

    def test_failed_assessment_keeps_reservation_and_cannot_be_repeated(self):
        pull = {'number': 11, 'head': {'sha': HEAD}}
        review = {'id': 4, 'commit_id': HEAD, 'state': 'COMMENTED',
                  'user': {'login': 'codex'}, 'body': 'A correction is required.'}
        comments, writes = [], []
        def pages(path):
            if path.endswith('/reviews'):
                return [review]
            if '/reviews/' in path:
                return []
            return comments
        def github(path, *, method, data):
            writes.append(data['body'])
            self.assertEqual(method, 'POST')
            item = {'id': 100, 'user': {'login': s.AUTHOR}, 'body': data['body']}
            comments.append(item)
            return item
        with patch.object(s, 'pages', side_effect=pages), patch.object(s, 'gh', side_effect=github), \
                patch.object(s, 'ordinary_worker_pending', return_value=False), \
                patch.object(s, 'active_goal_work', return_value=False), patch.object(s, 'refresh_guard'), \
                patch.object(s, 'evidence_for', return_value={'head': HEAD}), \
                patch.object(s, 'assess', side_effect=s.Stop('Ambiguous assessment')) as model, \
                patch.object(s, 'cursor') as worker, contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(s.Stop):
                s.run_one(pull, 3)
            s.run_one(pull, 3)
            model.assert_called_once_with({'head': HEAD})
            worker.assert_not_called()
        self.assertEqual(len(writes), 1)
        state = s.records(comments)[0][1]
        self.assertEqual(state['phase'], 'reserved')
        self.assertEqual(state['backend'], 'anthropic-wif')
        self.assertEqual(state['model'], 'claude-sonnet-5-5')

    def assert_not_running(self, pid):
        # A killed orphan may briefly remain a zombie until container PID 1
        # reaps it. It cannot execute or retain the credential-bearing runtime.
        path = Path(f'/proc/{pid}/stat')
        for _ in range(50):
            if not path.exists() or path.read_text().split()[2] == 'Z':
                return
            time.sleep(0.02)
        self.fail(f'Owned helper process {pid} is still running')

    def test_timeout_terminates_ignoring_child_and_grandchild_as_one_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'pids'
            term_file = Path(directory) / 'term'
            source = f'''
                import json, os, signal, subprocess, sys, time
                sys.stdin.read()
                signal.signal(signal.SIGTERM, lambda *_: open({str(term_file)!r}, 'w').write('cancelled'))
                child = subprocess.Popen([sys.executable, '-I', '-c',
                    'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
                open({str(pid_file)!r}, 'w').write(json.dumps([os.getpid(), child.pid]))
                print('{{', flush=True)
                time.sleep(60)
            '''
            original_popen = subprocess.Popen
            with self.helper(source), patch.object(s, 'ASSESSOR_TIMEOUT_SECONDS', 0.4), \
                    patch.object(s, 'ASSESSOR_TERMINATE_GRACE_SECONDS', 0.1), \
                    patch.object(s.subprocess, 'Popen', wraps=original_popen) as starts:
                with self.assertRaisesRegex(s.Stop, 'timed out; no automatic replay'):
                    s.assess({'head': HEAD})
                starts.assert_called_once()
            self.assertTrue(term_file.exists())
            for pid in json.loads(pid_file.read_text()):
                self.assert_not_running(pid)

    def test_parent_cancellation_stops_helper_and_restores_signal_handlers(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'pid'
            source = f'''
                import os, signal, sys, time
                sys.stdin.read()
                open({str(pid_file)!r}, 'w').write(str(os.getpid()))
                os.kill(os.getppid(), signal.SIGTERM)
                time.sleep(60)
            '''
            before = {sig: signal.getsignal(sig) for sig in [signal.SIGTERM, signal.SIGINT]}
            with self.helper(source), patch.object(s, 'ASSESSOR_TIMEOUT_SECONDS', 2):
                with self.assertRaisesRegex(s.AssessmentCancelled, 'cancelled; no automatic replay'):
                    s.assess({'head': HEAD})
            self.assert_not_running(int(pid_file.read_text()))
            self.assertEqual(before, {sig: signal.getsignal(sig) for sig in before})

    def test_successful_helper_cannot_leave_background_process_running(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'pid'
            source = f'''
                import subprocess, sys
                sys.stdin.read()
                child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])
                open({str(pid_file)!r}, 'w').write(str(child.pid))
                print({json.dumps(ENVELOPE)!r})
            '''
            with self.helper(source):
                self.assertEqual(s.assess({'head': HEAD}), (DECISION, USAGE))
            self.assert_not_running(int(pid_file.read_text()))


if __name__ == '__main__':
    unittest.main()
