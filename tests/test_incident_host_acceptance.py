"""Zero-model production mapper, real CLI/permission child and storage matrix.

RPC rows are explicitly synthetic; none of these tests certifies native Hooks.
"""
from __future__ import annotations

import copy
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_cg122_p0_counterexamples import P0Harness, cg
from tools.validation import incident_host_acceptance as h
from tools.validation import incident_readonly_child as child
from tools.validation import stop_host_acceptance as base


class IncidentHostTests(P0Harness):
    def ready(self):
        self.activate()
        self.plan = {'source': {'head': 'a' * 40, 'prepared_source_sha256': 'e' * 64,
                                'dirty_paths': [], 'renamed_away': []},
                     'runtime_sha256': 'b' * 64, 'cli_sha256': 'c' * 64,
                     'cli_version': 'codex-cli 0.160.0', 'toolkit': h.toolkit(),
                     'platform': platform.system(), 'python': str(Path(sys.executable).resolve()),
                     'plugin_root': str(h.ROOT), 'data_root': str(self.root / 'private'),
                     'cwd': str(self.root)}
        self.inventory = {event: {'key': event, 'eventName': event,
                                 'sourcePath': str(h.ROOT / 'hooks/hooks.json'),
                                 'source': 'plugin', 'handlerType': 'command',
                                 'displayOrder': i, 'async': False,
                                 'trustStatus': 'trusted', 'enabled': True, 'currentHash': 'd' * 64}
                          for i, event in enumerate(sorted(base.EVENTS))}
        self.capture = {'schema': 'incident-host-capture/v1', 'origin': 'synthetic',
                        'plan': self.plan, 'plan_sha256': h.plan_identity(self.plan),
                        'inventory': self.inventory, 'stages': {}, 'cleanups': []}
        self.manifest = base.read_json(h.MANIFEST)
        return self.capture

    def hook(self, name, turn, statuses=('completed',)):
        rows = []
        for status in statuses:
            inv = self.inventory[name]
            run = {**inv, 'id': name, 'executionMode': 'sync', 'status': 'running', 'durationMs': None, 'entries': []}
            for method in ('hook/started', 'hook/completed'):
                current = dict(run)
                if method == 'hook/completed':
                    current.update(status=status, durationMs=4)
                rows.append({'method': method, 'params': {'threadId': 'p0', 'turnId': turn, 'run': current}})
        return rows

    def stage(self, name, *, query_options=None):
        prompt = self.manifest['prompts'][name]
        prompt_result = self.prompt(prompt)
        state = self.state()
        turn = state['completion_attempt']['turn_id']
        rows = self.hook('userPromptSubmit', turn)
        rows[-1]['params']['run']['entries'] = [{'kind': 'context', 'text':
            prompt_result['hookSpecificOutput']['additionalContext']}]
        if query_options is not None:
            argv = [self.plan['python'], str(h.ROOT / 'scripts/context_guard.py'),
                    'checkpoint-status', '--data-dir', self.plan['data_root'],
                    '--session-id', 'p0', '--turn-id', turn, '--token', 'p0token', *query_options]
            pre = self.dispatch('PreToolUse', turn_id=turn, tool_name='shell',
                                tool_input={'command': cg.shell_join(argv)})
            self.assertEqual(pre, {}, 'frozen source Pre diagnostic branch must stay silent')
            p = subprocess.run(argv, capture_output=True, text=True, check=False,
                               env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            item = {'type': 'commandExecution', 'id': 'command-' + name,
                    'command': cg.shell_join(argv), 'cwd': self.plan['cwd'], 'source': 'agent',
                    'status': 'inProgress'}
            rows += self.hook('preToolUse', turn)
            rows.append({'method': 'item/started', 'params': {'threadId': 'p0', 'turnId': turn, 'item': item}})
            done = dict(item, status='completed' if p.returncode == 0 else 'failed',
                        exitCode=p.returncode, aggregatedOutput=p.stdout + p.stderr)
            rows.append({'method': 'item/completed', 'params': {'threadId': 'p0', 'turnId': turn, 'item': done}})
            post = self.dispatch('PostToolUse', turn_id=turn, tool_name='shell',
                                 tool_input={'command': item['command']},
                                 tool_response={'exit_code': p.returncode})
            rows += self.hook('postToolUse', turn,
                              ('blocked',) if post.get('decision') == 'block' else ('completed',))
        answer = {'pending': '等待后续安排。', 'pause': '已暂停，改动已保留。',
                  'resume': '继续保留待办。', 'typed': '等待指定标记。',
                  'typed_resume': '等待指定标记。'}.get(name, '诊断结束，验收仍等待。')
        self.dispatch('Stop', last_assistant_message=answer)
        rows += self.hook('stop', turn)
        dest = self.root / ('snapshot-' + name)
        h.copy_session(self.plan, 'p0', dest)
        stage = {'thread': 'p0', 'turn': turn, 'rows': rows, 'snapshot': str(dest),
                 'prompt_sha256': __import__('hashlib').sha256(prompt.encode()).hexdigest()}
        self.capture['stages'][name] = stage
        return stage

    def test_pause_provenance_and_old_pending_positive_negative(self):
        capture = self.ready()
        for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
            self.stage(name)
        result = h.map_capture(capture)
        self.assertEqual([result['gates'][n] for n in ('pause_same_unit', 'resume_provenance_pending',
                                                       'typed_wait_retained')], ['passed'] * 3)
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['native_acceptance'], 'not_run')
        states = [h.state_for(capture['stages'][n]) for n in ('pending', 'pause', 'resume', 'typed_resume')]
        for field in ('condition_id', 'raised_by_source', 'source_clause_sha256', 'released_by_source'):
            bad = copy.deepcopy(states)
            bad[2]['wait_conditions'][0][field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.pause_oracle(*bad)
        bad = copy.deepcopy(states)
        bad[2]['requirements'] = []
        with self.assertRaises(ValueError):
            h.pause_oracle(*bad)

    def test_status_real_cli_negative_controls_and_raw_field_matrix(self):
        capture = self.ready()
        self.stage('status', query_options=['--commands'])
        self.stage('unknown', query_options=['--unknown-status-option'])
        self.stage('missing', query_options=['--item', '--commands'])
        result = h.map_capture(capture)
        self.assertEqual(result['gates']['status_cli_posttool'], 'passed')
        self.assertEqual(result['gates']['status_negative_controls'], 'passed')
        stage = capture['stages']['status']
        for value in (None, True, '0', 1):
            bad = copy.deepcopy(stage)
            item = next(r['params']['item'] for r in bad['rows'] if r['method'] == 'item/completed')
            item['exitCode'] = value
            with self.subTest(value=value):
                if type(value) is not int:
                    with self.assertRaises(ValueError):
                        h.command_observation(bad, self.inventory, self.plan)
                else:
                    changed = copy.deepcopy(capture)
                    changed['stages']['status'] = bad
                    with self.assertRaises(ValueError):
                        h.map_capture(changed)
        for name in ('postToolUse', 'preToolUse'):
            bad = copy.deepcopy(stage)
            bad['rows'] = [r for r in bad['rows'] if r.get('params', {}).get('run', {}).get('eventName') != name]
            with self.assertRaises(ValueError):
                h.command_observation(bad, self.inventory, self.plan)
        bad = copy.deepcopy(stage)
        bad['rows'] += [next(r for r in stage['rows'] if r['method'] == 'item/completed')]
        with self.assertRaises(ValueError):
            h.command_observation(bad, self.inventory, self.plan)

    def command_sources(self, stage, started, completed):
        stage = copy.deepcopy(stage)
        for row in stage['rows']:
            if row['method'] in ('item/started', 'item/completed'):
                row['params']['item']['source'] = (started if row['method'] == 'item/started'
                                                  else completed)
        return stage

    def test_cli0160_initial_command_sources_share_all_query_oracles(self):
        self.ready()
        stages = {name: self.stage(name, query_options=options) for name, options in (
            ('status', ['--commands']), ('unknown', ['--unknown-status-option']),
            ('missing', ['--item', '--commands']))}
        for source in ('agent', 'unifiedExecStartup'):
            with self.subTest(source=source):
                stage = self.command_sources(stages['status'], source, source)
                item = h.command_observation(stage, self.inventory, self.plan)
                h.status_argv(item, stage, self.plan)
                self.assertEqual(item['source'], source)
                for name in ('unknown', 'missing'):
                    stage = self.command_sources(stages[name], source, source)
                    self.assertEqual(h.rejection_observation(
                        stage, self.inventory, self.plan, name)['branch'], 'cli2_post_blocked')

    def wrap_command(self, stage, prefix='/bin/zsh -lc'):
        stage = copy.deepcopy(stage)
        for row in stage['rows']:
            if row['method'] in ('item/started', 'item/completed'):
                item = row['params']['item']
                item['command'] = prefix + ' ' + __import__('shlex').quote(item['command'])
        return stage

    def test_cli0160_single_shell_wrapper_status_and_negative_controls(self):
        self.ready()
        for name, options in (('status', ['--commands']),
                              ('unknown', ['--unknown-status-option']),
                              ('missing', ['--item', '--commands'])):
            stage = self.command_sources(self.stage(name, query_options=options),
                                         'unifiedExecStartup', 'unifiedExecStartup')
            stage = self.wrap_command(stage)
            with self.subTest(name=name):
                if name == 'status':
                    item = h.command_observation(stage, self.inventory, self.plan)
                    argv = h.status_argv(item, stage, self.plan)
                    self.assertEqual(argv[2], 'checkpoint-status')
                else:
                    self.assertEqual(h.rejection_observation(
                        stage, self.inventory, self.plan, name)['branch'], 'cli2_post_blocked')

    def test_cli0160_redacted_display_sentinel_is_not_a_reconstructed_secret(self):
        self.ready()
        stage = self.stage('status', query_options=['--commands'])
        for row in stage['rows']:
            if row['method'] in ('item/started', 'item/completed'):
                item = row['params']['item']
                item['command'] = item['command'].replace('--token p0token',
                                                         '--token=[REDACTED_SECRET]')
        stage = self.wrap_command(stage)
        item = h.command_observation(stage, self.inventory, self.plan)
        self.assertIn('--token=[REDACTED_SECRET]', h.status_argv(item, stage, self.plan))
        for wrong in ('[OTHER]', '[REDACTED_SECRET]*', '[REDACTED_SECRET]$(echo extra)'):
            command = item['command'].replace('[REDACTED_SECRET]', wrong)
            self.assertIsNone(h.ordinary_command_argv(command, windows=False))
        self.assertIsNone(h.ordinary_command_argv(
            '/bin/zsh -lc ' + __import__('shlex').quote(
                '/literal/python /literal/script --data-dir=[REDACTED_SECRET]'), windows=False))

    def redacted_stage(self):
        stage = self.stage('status', query_options=['--commands'])
        for row in stage['rows']:
            if row['method'] in ('item/started', 'item/completed'):
                item = row['params']['item']
                item['command'] = item['command'].replace('--token p0token',
                                                         '--token=[REDACTED_SECRET]')
        return self.wrap_command(stage)

    @unittest.skipIf(os.name == 'nt' or (hasattr(os, 'geteuid') and os.geteuid() == 0),
                     'real restricted fixture uses non-root POSIX child; native Windows separate')
    def test_cli0160_redacted_fixture_real_child_and_mapper_chain(self):
        self.ready()
        stage = self.redacted_stage()
        self.capture['stages']['status'] = stage
        item = h.command_observation(stage, self.inventory, self.plan)
        fixture = self.root / 'redacted-fixture'
        fixture.mkdir()
        request = h.make_fixture(self.plan, stage, item, fixture, inventory=self.inventory)
        try:
            record = child.witness(request)
            self.assertEqual(child.judge(record, request), 'passed')
            self.assertEqual(record['before'], record['after'])
            self.assertNotIn('[REDACTED_SECRET]', request['argv'])
            readonly = copy.deepcopy(stage)
            argv = [self.plan['python'], str(h.ROOT / 'tools/validation/incident_readonly_child.py'),
                    '--request', str(self.root / 'private-request.json')]
            for row in readonly['rows']:
                if row.get('method') in ('item/started', 'item/completed'):
                    row['params']['item']['command'] = cg.shell_join(argv)
                    if row['method'] == 'item/completed':
                        row['params']['item']['aggregatedOutput'] = json.dumps(record)
            self.capture.update(readonly_request=request, readonly_tool_argv=argv)
            self.capture['stages']['readonly'] = self.wrap_command(readonly)
            result = h.map_capture(self.capture)
            self.assertEqual(result['gates']['status_cli_posttool'], 'passed')
            self.assertEqual(result['gates']['restricted_child_readonly'], 'passed')
            self.assertEqual(result['native_acceptance'], 'not_run')
        finally:
            child.restore(fixture, request['restriction'])
        __import__('shutil').rmtree(fixture)
        self.assertFalse(fixture.exists())

    def test_cli0160_fixture_output_authority_negative_matrix(self):
        self.ready()
        original = self.redacted_stage()
        item = h.command_observation(original, self.inventory, self.plan)
        output = json.loads(item['aggregatedOutput'])
        variants = []
        for field, value in (('turn_id', 'wrong-turn'), ('revision', 'bad'),
                             ('revision', 'z' * 64), ('advanced_commands', {})):
            changed = copy.deepcopy(output)
            changed[field] = value
            variants.append(changed)
        changed = copy.deepcopy(output)
        changed['advanced_commands']['status'] = None
        variants.append(changed)
        raw_variants = [json.dumps(v) for v in variants]
        raw_variants.append(json.dumps(output).replace('"turn_id":', '"turn_id":"duplicate", "turn_id":', 1))
        for index, raw in enumerate(raw_variants):
            bad = copy.deepcopy(original)
            terminal = next(row['params']['item'] for row in bad['rows']
                            if row.get('method') == 'item/completed'
                            and row['params']['item'].get('type') == 'commandExecution')
            terminal['aggregatedOutput'] = raw
            root = self.root / ('negative-fixture-' + str(index))
            root.mkdir()
            with self.subTest(index=index), self.assertRaises((ValueError, RuntimeError)):
                h.make_fixture(self.plan, bad, terminal, root, inventory=self.inventory)

    def test_cli0160_all_four_inventory_commands_require_exact_authority(self):
        self.ready()
        original = self.redacted_stage()
        terminal = h.command_observation(original, self.inventory, self.plan)
        output = json.loads(terminal['aggregatedOutput'])
        for name, command in output['advanced_commands'].items():
            tokens = cg.private_control_command_tokens(command, windows=os.name == 'nt')
            changes = [(0, '/other/python'), (1, '/other/script'), (2, 'status-other')]
            for flag, value in (('--data-dir', '/other/data'), ('--session-id', 'other-session'),
                                ('--turn-id', 'other-turn')):
                changes.append((tokens.index(flag) + 1, value))
            token_index = next(i for i, token in enumerate(tokens) if token.startswith('--token='))
            changes.extend([(token_index, '--token=wrong-token'),
                            (token_index, '--token=[REDACTED_SECRET]')])
            if name == 'register_proof':
                changes.append((len(tokens) - 1, '/other/manifest.json'))
            for index, value in changes:
                changed = list(tokens)
                changed[index] = value
                bad_output = copy.deepcopy(output)
                bad_output['advanced_commands'][name] = cg.shell_join(changed)
                bad = copy.deepcopy(original)
                item = next(row['params']['item'] for row in bad['rows']
                            if row.get('method') == 'item/completed'
                            and row['params']['item'].get('type') == 'commandExecution')
                item['aggregatedOutput'] = json.dumps(bad_output)
                with self.subTest(command=name, index=index), self.assertRaises((ValueError, RuntimeError)):
                    h.status_output(item, bad, self.plan)
            for suffix in (' --commands', ' --data-dir /other', '; echo extra'):
                bad_output = copy.deepcopy(output)
                bad_output['advanced_commands'][name] = command + suffix
                bad = copy.deepcopy(original)
                item = next(row['params']['item'] for row in bad['rows']
                            if row.get('method') == 'item/completed'
                            and row['params']['item'].get('type') == 'commandExecution')
                item['aggregatedOutput'] = json.dumps(bad_output)
                with self.subTest(command=name, suffix=suffix), self.assertRaises(ValueError):
                    h.status_output(item, bad, self.plan)

    def test_cli0160_fixture_hook_authority_negative_matrix(self):
        self.ready()
        original = self.redacted_stage()
        prompt = next(row['params']['run'] for row in original['rows']
                      if row.get('method') == 'hook/completed'
                      and row['params']['run']['eventName'] == 'userPromptSubmit')
        text = prompt['entries'][0]['text']
        variants = [[], [{'kind': 'context', 'text': ''}],
                    [{'kind': 'message', 'text': text}],
                    [{'kind': 'context', 'text': text}, {'kind': 'context', 'text': text}]]
        for old, new in ((sys.executable, '/other/python'),
                         (str(h.ROOT / 'scripts/context_guard.py'), '/other/script'),
                         ('--session-id p0', '--session-id other'),
                         ('--turn-id ', '--turn-id other-'),
                         (self.plan['data_root'], '/other/data'),
                         ('p0token', 'wrong-token'), ('p0token', '[REDACTED_SECRET]')):
            changed = text.replace(old, new)
            self.assertNotEqual(changed, text, 'negative control must change an input')
            variants.append([{'kind': 'context', 'text': changed}])
        for index, entries in enumerate(variants):
            bad = copy.deepcopy(original)
            next(row['params']['run'] for row in bad['rows']
                 if row.get('method') == 'hook/completed'
                 and row['params']['run']['eventName'] == 'userPromptSubmit')['entries'] = entries
            item = h.command_observation(bad, self.inventory, self.plan)
            root = self.root / ('hook-negative-fixture-' + str(index))
            root.mkdir()
            with self.subTest(index=index), self.assertRaises((ValueError, RuntimeError)):
                h.make_fixture(self.plan, bad, item, root, inventory=self.inventory)

    def test_cli0160_unredacted_fixture_token_must_match_copied_authority(self):
        self.ready()
        original = self.stage('status', query_options=['--commands'])
        for marker in ('wrong-token', '[OTHER]'):
            bad = copy.deepcopy(original)
            for row in bad['rows']:
                if row.get('method') in ('item/started', 'item/completed'):
                    row['params']['item']['command'] = row['params']['item']['command'].replace('p0token', marker)
            terminal = h.command_observation(bad, self.inventory, self.plan)
            root = self.root / ('wrong-fixture-' + str(len(marker)))
            root.mkdir()
            with self.subTest(marker=marker), self.assertRaises(RuntimeError):
                h.make_fixture(self.plan, bad, terminal, root, inventory=self.inventory)

    def test_cli0160_wrapper_parser_exact_platform_forms(self):
        command = '"/literal path/python" "/literal path/script.py" --request "a [b]"'
        expected = ['/literal path/python', '/literal path/script.py', '--request', 'a [b]']
        for shell in ('/bin/zsh -lc', '/bin/bash -lc', '/bin/sh -c'):
            with self.subTest(shell=shell):
                self.assertEqual(h.ordinary_command_argv(
                    shell + ' ' + __import__('shlex').quote(command), windows=False), expected)
        # Existing host-terminal fixture defines exactly pwsh.exe -Command.
        for shell in ('pwsh.exe', 'powershell.exe'):
            self.assertEqual(h.ordinary_command_argv(
                shell + " -Command '" + command + "'", windows=True), expected)
        self.assertIsNone(h.ordinary_command_argv(
            'cmd.exe /c "' + command + '"', windows=True))

    def test_cli0160_windows_absolute_shell_is_bound_and_preserves_call_operator(self):
        shell = r'C:\Example Space\native\powershell\pwsh.exe'
        identity = {'name': 'powershell', 'path': shell, 'sha256': 'a' * 64}
        body = r'& "C:\Python Space\python.exe" "C:\Plugin Space\context_guard.py" checkpoint-status --token=[REDACTED_SECRET]'
        expected = [r'C:\Python Space\python.exe', r'C:\Plugin Space\context_guard.py',
                    'checkpoint-status', '--token=[REDACTED_SECRET]']
        for command in (subprocess.list2cmdline([shell, '-Command', body]),
                        '"' + shell + '" -Command ' + "'" + body + "'",
                        '& "' + shell + '" -Command ' + "'" + body + "'"):
            with self.subTest(command=command):
                self.assertEqual(h.ordinary_command_argv(command, windows=True,
                                                        shell_identity=identity), expected)
                self.assertIsNone(h.ordinary_command_argv(command, windows=True))
                wrong = {**identity, 'path': r'C:\Other\pwsh.exe'}
                self.assertIsNone(h.ordinary_command_argv(command, windows=True,
                                                         shell_identity=wrong))
                self.assertIsNone(h.ordinary_command_argv(command, windows=True,
                                                         shell_identity={**identity, 'sha256': None}))
        for flags in ('-NoProfile -Command', '-EncodedCommand', '-Command extra'):
            self.assertIsNone(h.ordinary_command_argv(
                '"' + shell + '" ' + flags + ' ' + "'" + body + "'", windows=True,
                shell_identity=identity))
        for suffix in ('; echo extra', ' | more', ' > output', ' $(extra)'):
            self.assertIsNone(h.ordinary_command_argv(
                subprocess.list2cmdline([shell, '-Command', body + suffix]), windows=True,
                shell_identity=identity))
        self.assertEqual(h.ordinary_command_argv(body, windows=True), expected)
        # Bare aliases remain synthetic compatibility; a native plan pins a path.
        self.assertEqual(h.ordinary_command_argv("pwsh.exe -Command '" + body + "'",
                                                windows=True), expected)
        self.assertIsNone(h.ordinary_command_argv("pwsh.exe -Command '" + body + "'",
                                                 windows=True, shell_identity=identity))

    def test_cli0160_windows_shell_file_hash_and_official_readback_fail_closed(self):
        self.ready()
        shell = self.root / 'pwsh.exe'
        shell.write_bytes(b'example shell bytes')
        identity = {'name': 'powershell', 'path': str(shell), 'sha256': base.sha(shell)}
        self.assertEqual(h.verify_shell_file(identity), identity)
        for changed in ({**identity, 'sha256': '0' * 64}, {**identity, 'path': str(self.root)},
                        {**identity, 'name': 'unknown'}, {**identity, 'path': 'pwsh.exe'}):
            with self.subTest(identity=changed), self.assertRaises(ValueError):
                h.verify_shell_file(changed)
        client = object.__new__(h.Client)
        client.plan = {**self.plan, 'platform': 'Windows', 'shell': identity, 'model': 'example'}
        for observed in ({'name': 'powershell', 'path': str(self.root / 'other.exe')},
                         {'name': 'unknown', 'path': str(shell)}, None):
            client.rpc = mock.Mock(return_value={'shell': observed})
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                client.start()
            client.rpc.assert_called_once_with('environment/info', {'environmentId': 'local'})
        for sandbox, passes in (('workspaceWrite', True), ('readOnly', False)):
            client.rpc = mock.Mock(side_effect=[{'shell': {'name': 'powershell', 'path': str(shell)}},
                {'model': 'example', 'approvalPolicy': 'on-request', 'sandbox': {'type': sandbox},
                 'thread': {'id': 'example-thread'}}])
            if passes:
                self.assertEqual(client.start(), 'example-thread')
            else:
                with self.assertRaises(ValueError):
                    client.start()
            self.assertEqual(client.rpc.call_args_list[0], mock.call(
                'environment/info', {'environmentId': 'local'}))
        client.plan['shell'] = {**identity, 'sha256': '0' * 64}
        client.rpc = mock.Mock()
        with self.assertRaises(ValueError):
            client.start()
        client.rpc.assert_not_called()

    def test_cli0160_wrapper_rejects_injection_nesting_extra_args_and_binding_drift(self):
        self.ready()
        original = self.stage('status', query_options=['--commands'])
        command = next(row['params']['item']['command'] for row in original['rows']
                       if row['method'] == 'item/completed')
        quote = __import__('shlex').quote
        hostile = [command + tail for tail in ('; echo extra', ' && echo extra',
                   ' | cat', ' > output', '\ntrue', ' $(echo extra)', ' `echo extra`')]
        hostile += [quote('/bin/zsh') + ' -lc ' + quote(command),
                    command.replace('--commands', '--data-dir /other --commands')]
        for body in hostile:
            bad = self.wrap_command(original)
            for row in bad['rows']:
                if row['method'] in ('item/started', 'item/completed'):
                    row['params']['item']['command'] = '/bin/zsh -lc ' + quote(body)
            with self.subTest(body=body), self.assertRaises(ValueError):
                h.status_argv(h.command_observation(bad, self.inventory, self.plan), bad, self.plan)
        for outer in ('/bin/zsh -lc ' + quote(command) + ' extra',
                      '/bin/zsh -ilc ' + quote(command),
                      '/other/zsh -lc ' + quote(command),
                      '/bin/zsh -lc ' + quote(command) + '; true'):
            self.assertIsNone(h.ordinary_command_argv(outer, windows=False))
        for old, new in ((self.plan['python'], '/other/python'),
                         (str(h.ROOT / 'scripts/context_guard.py'), '/other/script.py'),
                         ('--session-id p0', '--session-id other'),
                         ('--turn-id ', '--turn-id other-')):
            bad = self.wrap_command(original)
            for row in bad['rows']:
                if row['method'] in ('item/started', 'item/completed'):
                    row['params']['item']['command'] = '/bin/zsh -lc ' + quote(command.replace(old, new))
            with self.subTest(binding=old), self.assertRaises(ValueError):
                h.status_argv(h.command_observation(bad, self.inventory, self.plan), bad, self.plan)

    def test_cli0160_source_pair_matrix_rejects_manual_followup_and_mismatch(self):
        self.ready()
        original = self.stage('status', query_options=['--commands'])
        sources = ('agent', 'unifiedExecStartup', 'userShell', 'unifiedExecInteraction',
                   'unknown', '', None, True, [], {})
        for started in sources:
            for completed in sources:
                if started == completed and started in ('agent', 'unifiedExecStartup'):
                    continue
                with self.subTest(started=started, completed=completed):
                    with self.assertRaises(ValueError):
                        h.command_observation(self.command_sources(original, started, completed),
                                              self.inventory, self.plan)
        for method in ('item/started', 'item/completed'):
            missing = copy.deepcopy(original)
            next(row['params']['item'] for row in missing['rows']
                 if row['method'] == method).pop('source')
            with self.subTest(missing_source=method), self.assertRaises(ValueError):
                h.command_observation(missing, self.inventory, self.plan)

    def test_cli0160_startup_preserves_command_identity_and_scope_checks(self):
        self.ready()
        original = self.command_sources(self.stage('status', query_options=['--commands']),
                                        'unifiedExecStartup', 'unifiedExecStartup')
        for field, value in (('id', 'other-command'), ('command', 'other-command'),
                             ('cwd', str(self.root / 'other'))):
            bad = copy.deepcopy(original)
            next(row['params']['item'] for row in bad['rows']
                 if row['method'] == 'item/started')[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.command_observation(bad, self.inventory, self.plan)
        for field in ('threadId', 'turnId'):
            bad = copy.deepcopy(original)
            next(row['params'] for row in bad['rows']
                 if row['method'] == 'item/started')[field] = 'other-scope'
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.command_observation(bad, self.inventory, self.plan)

    def test_observed_windows_principal_is_bound_to_exact_ordinary_tool(self):
        self.ready()
        stage = self.stage('status', query_options=['--commands'])
        plan = {**self.plan, 'platform': 'Windows'}
        argv = [plan['python'], str(h.ROOT / 'tools/validation/incident_readonly_child.py'), '--identity']
        sid = 'S-1-5-21-123'
        for row in stage['rows']:
            if row['method'] in ('item/started', 'item/completed'):
                row['params']['item']['command'] = cg.shell_join(argv)
                if row['method'] == 'item/completed':
                    row['params']['item']['aggregatedOutput'] = json.dumps(
                        {'schema': 'incident-child-principal/v1', 'sid': sid, 'pid': 12, 'platform': 'Windows'})
        self.assertEqual(h.principal_observation(stage, self.inventory, plan), sid)
        for key, value in [('sid', 'invalid'), ('pid', True), ('platform', 'Darwin'), ('schema', 'other')]:
            bad = copy.deepcopy(stage)
            completed = next(r['params']['item'] for r in bad['rows'] if r['method'] == 'item/completed')
            record = json.loads(completed['aggregatedOutput'])
            record[key] = value
            completed['aggregatedOutput'] = json.dumps(record)
            with self.subTest(key=key), self.assertRaises(ValueError):
                h.principal_observation(bad, self.inventory, plan)
        bad = copy.deepcopy(stage)
        for row in bad['rows']:
            if row['method'] in ('item/started', 'item/completed'):
                row['params']['item']['command'] += ' --request other'
        with self.assertRaises(ValueError):
            h.principal_observation(bad, self.inventory, plan)

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'POSIX root cannot prove write denial')
    def test_actual_readonly_child_with_real_query_and_denied_lock(self):
        self.ready()
        stage = self.stage('status', query_options=['--commands'])
        item = h.command_observation(stage, self.inventory, self.plan)
        root = self.root / 'readonly'
        root.mkdir()
        request = h.make_fixture(self.plan, stage, item, root, inventory=self.inventory,
                                 principal=child.current_sid() if os.name == 'nt' else None)
        try:
            record = child.witness(request)
            self.assertEqual(child.judge(record, request), 'passed')
            self.assertEqual(record['before'], record['after'])
            for key, value in [('pid', True), ('cli_exit_code', None), ('write_attempts', []),
                               ('request_sha256', 'bad')]:
                bad = copy.deepcopy(record)
                bad[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    child.judge(bad, request)
            bad = copy.deepcopy(record)
            bad['write_attempts'][0]['errno'] = 0
            self.assertEqual(child.judge(bad, request), 'failed')
        finally:
            child.restore(root, request['restriction'])

    def test_malformed_native_rejection_branches_and_not_observed(self):
        self.ready()
        stage = self.stage('unknown', query_options=['--unknown-status-option'])
        result = h.rejection_observation(stage, self.inventory, self.plan, 'unknown')
        self.assertEqual(result['branch'], 'cli2_post_blocked')
        for value in (None, True, '2', 0):
            bad = copy.deepcopy(stage)
            next(r['params']['item'] for r in bad['rows'] if r['method'] == 'item/completed')['exitCode'] = value
            if value is None:
                self.assertEqual(h.rejection_observation(bad, self.inventory, self.plan, 'unknown')['status'], 'pending')
            else:
                with self.assertRaises(ValueError):
                    h.rejection_observation(bad, self.inventory, self.plan, 'unknown')
        bad = copy.deepcopy(stage)
        next(r['params']['run'] for r in bad['rows'] if r['method'] == 'hook/completed'
             and r['params']['run']['eventName'] == 'postToolUse')['status'] = 'completed'
        with self.assertRaises(ValueError):
            h.rejection_observation(bad, self.inventory, self.plan, 'unknown')
        refused = copy.deepcopy(stage)
        refused['rows'] = [r for r in refused['rows']
                           if r.get('params', {}).get('run', {}).get('eventName') != 'postToolUse']
        next(r['params']['run'] for r in refused['rows'] if r['method'] == 'hook/completed'
             and r['params']['run']['eventName'] == 'preToolUse')['status'] = 'blocked'
        terminal = next(r['params']['item'] for r in refused['rows'] if r['method'] == 'item/completed')
        terminal.update(status='failed', exitCode=None)
        self.assertEqual(h.rejection_observation(refused, self.inventory, self.plan, 'unknown'),
                         {'status': 'pending', 'branch': 'pre_blocked',
                          'cli': 'not_observed', 'posttool': 'not_observed'})
        missing = copy.deepcopy(refused)
        missing['rows'] = [r for r in missing['rows'] if r['method'] not in ('item/started', 'item/completed')]
        self.assertEqual(h.rejection_observation(missing, self.inventory, self.plan, 'unknown')['status'], 'pending')

    def test_inventory_foreign_source_boolean_and_prompt_relabel_rejected(self):
        capture = self.ready()
        self.stage('status', query_options=['--commands'])
        for field, value in (('sourcePath', str(self.root / 'foreign-hooks.json')),
                             ('displayOrder', True), ('enabled', 1), ('currentHash', None)):
            bad = copy.deepcopy(capture)
            bad['inventory']['stop'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.map_capture(bad)
        bad = copy.deepcopy(capture)
        bad['stages']['status']['prompt_sha256'] = 'wrong'
        with self.assertRaises(ValueError):
            h.map_capture(bad)
        bad = copy.deepcopy(capture['stages']['status'])
        next(r['params']['run'] for r in bad['rows'] if r['method'] == 'hook/started')['displayOrder'] = True
        with self.assertRaises(ValueError):
            h.command_observation(bad, self.inventory, self.plan)

    def test_pending_capture_export_redaction_and_exclusive_storage(self):
        capture = self.ready()
        private = self.root / 'capture'
        private.mkdir()
        h.write_new(private / 'capture.json', capture)
        h.write_new(private / 'artifacts.json', {'capture.json': base.sha(private / 'capture.json')})
        output = private / 'result.json'
        result = h.map_bundle(private, output)
        self.assertEqual(result['status'], 'pending')
        raw = output.read_text()
        for forbidden in ('p0token', str(self.root), 'snapshot-', 'query_stdout', 'prompts'):
            self.assertNotIn(forbidden, raw)
        with self.assertRaises(ValueError):
            h.map_bundle(private, output)
        self.assertEqual(output.read_text(), raw)
        with self.assertRaises(FileExistsError):
            h.write_new(output, {})
        self.assertEqual(output.read_text(), raw)
        (private / 'capture.json').write_text('{}')
        with self.assertRaises(ValueError):
            h.map_bundle(private, private / 'retry-result.json')
        self.assertTrue(output.is_file())

    def stop_fixture(self):
        from tests import test_stop_host_acceptance as stop_tests
        fixture = stop_tests.HostOracleTests()
        root = self.root / 'stop'
        for name in ('first', 'cold'):
            (root / name).mkdir(parents=True)
        inventory = self.inventory
        def event_rows(turn, statuses=('completed',)):
            rows = self.hook('stop', turn, statuses)
            for r in rows:
                r['params']['threadId'] = 't'
            rows.append({'method': 'turn/completed', 'params': {
                'threadId': 't', 'turn': {'id': turn, 'status': 'completed'}}})
            return rows
        first = [{'direction': 'response', 'message': {'result': {'data': [{'hooks': list(inventory.values())}]}}}]
        first += [{'direction': 'response', 'message': row} for u in ('one', 'two', 'three')
                  for row in event_rows(u)]
        first.append({'direction': 'request', 'message': {'method': 'thread/compact/start'}})
        compact = fixture.compact_rows()
        for row in compact:
            if row['method'] in ('hook/started', 'hook/completed'):
                row['params']['run'].update(inventory['preCompact'])
        first += [{'direction': 'response', 'message': row} for row in compact]
        first.append({'direction': 'response', 'message': {'method': 'turn/completed', 'params': {
            'threadId': 't', 'turn': {'id': 'u', 'status': 'completed'}}}})
        cold = [{'direction': 'response', 'message': {'method': 'hook/completed', 'params': {
            'threadId': 't', 'run': {'eventName': 'sessionStart', 'status': 'completed'}}}}]
        cold += [{'direction': 'response', 'message': row} for row in event_rows('four')]
        cold += [{'direction': 'response', 'message': row} for row in event_rows('five', ('blocked', 'completed'))]
        for name, rows in (('first', first), ('cold', cold)):
            (root / name / 'rpc.jsonl').write_text('\n'.join(json.dumps(r) for r in rows) + '\n')
        before = self.state()
        self.dispatch('PreCompact')
        self.dispatch('SessionStart', source='resume')
        self.prompt('继续保留待办。')
        after = self.state()
        self.prompt(base.WAIT)
        self.dispatch('Stop', last_assistant_message='当前任务已完成。')
        negative = self.state()
        for name, state in (('before-compact', before), ('after-resume', after), ('negative-state', negative)):
            h.write_new(root / (name + '.json'), state)
        cleanup = {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                   'process_group_cleanup_error': None}
        receipt = {'schema': 'stop-host-acceptance/v1', 'status': 'passed', 'source': self.plan['source'],
                   'runtime_sha256': self.plan['runtime_sha256'], 'cli_sha256': self.plan['cli_sha256'],
                   'cleanups': [cleanup, cleanup]}
        h.write_new(root / 'result.json', receipt)
        self.capture.update(stop_result=receipt, stop_directory=str(root), cleanups=[cleanup] * 3)
        return root

    @unittest.skipIf(os.name == 'nt' or (hasattr(os, 'geteuid') and os.geteuid() == 0),
                     'full synthetic fixture uses POSIX denial; not native acceptance')
    def test_full_synthetic_capture_mapping_export_and_inverted_controls(self):
        capture = self.ready()
        for name in ('pending', 'pause', 'resume', 'typed', 'typed_resume'):
            self.stage(name)
        status = self.stage('status', query_options=['--commands'])
        item = h.command_observation(status, self.inventory, self.plan)
        fixture = self.root / 'readonly-full'
        fixture.mkdir()
        request = h.make_fixture(self.plan, status, item, fixture, inventory=self.inventory)
        try:
            record = child.witness(request)
            self.stage('unknown', query_options=['--unknown-status-option'])
            self.stage('missing', query_options=['--item', '--commands'])
            stage = copy.deepcopy(capture['stages']['status'])
            argv = [self.plan['python'], str(h.ROOT / 'tools/validation/incident_readonly_child.py'),
                    '--request', str(self.root / 'request.json')]
            for row in stage['rows']:
                if row['method'] in ('item/started', 'item/completed'):
                    row['params']['item']['command'] = cg.shell_join(argv)
                    if row['method'] == 'item/completed':
                        row['params']['item']['aggregatedOutput'] = json.dumps(record)
            capture['stages']['readonly'] = stage
            capture['readonly_request'] = request
            capture['readonly_tool_argv'] = argv
            stop = self.stop_fixture()
            result = h.map_capture(capture)
            self.assertEqual(result['status'], 'passed')
            h.validate_result(result)
            wrapped = copy.deepcopy(capture)
            for name, original_stage in wrapped['stages'].items():
                wrapped['stages'][name] = self.wrap_command(original_stage)
            self.assertEqual(h.map_capture(wrapped)['status'], 'passed')
            bad_scope = copy.deepcopy(result)
            bad_scope['native_acceptance'] = 'passed'
            with self.assertRaises(ValueError):
                h.validate_result(bad_scope)
            self.assertEqual(set(result['gates'].values()), {'passed'})
            self.assertEqual(result['native_acceptance'], 'not_run')
            self.assertNotIn('p0token', json.dumps(result))
            h.write_new(self.root / 'capture.json', capture)
            catalog = {p.relative_to(self.root).as_posix(): base.sha(p)
                       for p in self.root.rglob('*') if p.is_file()}
            h.write_new(self.root / 'artifacts.json', catalog)
            exported = h.map_bundle(self.root, self.root / 'result.json')
            self.assertEqual(exported['status'], 'passed')
            self.assertEqual(exported['native_acceptance'], 'not_run')
            original_export = (self.root / 'result.json').read_bytes()
            with self.assertRaises(ValueError):
                h.map_bundle(self.root, self.root / 'result.json')
            self.assertEqual((self.root / 'result.json').read_bytes(), original_export)
            bad = copy.deepcopy(capture)
            bad['cleanups'][0]['owned_tree_no_running_members'] = False
            with self.assertRaises(ValueError):
                h.map_capture(bad)
            (stop / 'after-resume.json').write_text(json.dumps({'mode': {'active': True}, 'requirements': []}))
            with self.assertRaises((ValueError, h.cg.StateIntegrityError)):
                h.map_capture(capture)
        finally:
            child.restore(fixture, request['restriction'])

    def test_official_approval_is_pending_no_response(self):
        client = object.__new__(h.Client)
        with mock.patch.object(base.Client, 'receive', side_effect=ValueError('unexpected server request')):
            with self.assertRaises(h.ObservationPending):
                client.receive(0)

    def test_collect_retains_failed_capture_and_cleanup(self):
        self.ready()
        output = self.root / 'failed-output'
        cleanup = {'owned_process_exited': True, 'owned_tree_no_running_members': True,
                   'process_group_cleanup_error': None}
        fake = mock.Mock(inventory=self.inventory)
        fake.start.side_effect = h.ObservationPending('official request retained')
        fake.close.return_value = cleanup
        with mock.patch.object(h, 'Client', return_value=fake):
            capture = h.collect(self.plan, output)
        self.assertEqual(capture['pending_class'], 'ObservationPending')
        self.assertEqual(capture['cleanups'], [cleanup])
        self.assertTrue((output / 'capture.json').is_file())
        self.assertTrue((output / 'failure.json').is_file())
        self.assertEqual(h.map_capture(capture)['status'], 'pending')
        with self.assertRaises(FileExistsError):
            h.collect(self.plan, output)

    def test_windows_acl_adapter_and_principal_drift(self):
        sid = 'S-1-5-21-123'
        argv = child.acl_argv(Path('X:/owned-fixture'), sid)
        self.assertIn('*' + sid + ':(WD,AD,WEA,WA,DE)', argv[0])
        self.assertNotIn('/inheritance:r', argv[0])
        self.assertNotIn('/grant:r', argv[0])
        self.assertNotIn('/C', argv[0])
        self.assertNotIn('/T', argv[0])
        self.assertNotIn(':(W,D)', ' '.join(argv[0]))
        with self.assertRaises(ValueError):
            child.acl_argv(Path('/tmp/a'), 'user;command')
        request = {'inventory': {}, 'restriction': {'sid': sid}, 'turn': 'u', 'state_revision': 'rev'}
        request['request_sha256'] = h.plan_identity(request)
        record = {'schema': child.SCHEMA, 'request_sha256': request['request_sha256'], 'platform': 'Windows',
                  'pid': 4, 'ppid': 3, 'sid': sid, 'cli_exit_code': 0,
                  'write_attempts': [{'errno': 13}, {'errno': 13}],
                  'before': {}, 'after': {}, 'query_stdout': '{"advanced_commands":{},"turn_id":"u","revision":"rev"}'}
        self.assertEqual(child.judge(record, request), 'passed')
        record['sid'] = 'S-1-5-21-999'
        with self.assertRaises(ValueError):
            child.judge(record, request)


class PlanPinTests(unittest.TestCase):
    def test_cli_version_explicit_0160_and_old_default_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / 'codex'
            cli.write_text('cli')
            home = root / 'home'
            plugin = home / 'plugin'
            data = home / 'data'
            for p in (plugin, data):
                p.mkdir(parents=True)
            plan = {'schema': 'stop-host-plan/v1', 'repo': str(base.ROOT), 'codex': str(cli),
                    'home': str(home), 'cwd': str(root), 'plugin_root': str(plugin),
                    'data_root': str(data), 'cli_sha256': base.sha(cli), 'source': {},
                    'runtime_sha256': 'digest', 'cli_version': 'codex-cli 0.160.0'}
            path = root / 'plan.json'
            h.write_new(path, plan)
            with mock.patch.object(base.subprocess, 'check_output', return_value='codex-cli 0.160.0\n'), \
                    mock.patch.object(base, 'prepared_source_identity', return_value={}), \
                    mock.patch.object(base, 'runtime', return_value='digest'):
                self.assertEqual(base.preflight(path, root / 'output'), plan)
                del plan['cli_version']
                path.write_text(json.dumps(plan))
                with self.assertRaisesRegex(ValueError, 'version differs'):
                    base.preflight(path, root / 'output')

    def test_actual_preflight_argv_zero_models_and_retained_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / 'home'
            plugin = home / 'plugin'
            data = home / 'data'
            cwd = root / 'workspace'
            for p in (plugin, data, cwd):
                p.mkdir(parents=True)
            cli = root / 'fake-cli'
            cli.write_text('synthetic CLI bytes')
            cli.chmod(0o700)
            plan = {'schema': 'incident-host-plan/v1', 'repo': str(h.ROOT), 'codex': str(cli),
                    'output': str(root / 'output'),
                    'python': str(Path(sys.executable).resolve()), 'home': str(home), 'cwd': str(cwd),
                    'plugin_root': str(plugin), 'data_root': str(data), 'source': {'dirty_paths': [], 'renamed_away': []},
                    'runtime_sha256': 'digest', 'cli_version': 'codex-cli 0.160.0', 'cli_sha256': base.sha(cli),
                    'python_sha256': base.sha(Path(sys.executable).resolve()),
                    'python_version': subprocess.check_output([sys.executable, '--version'], text=True).strip(),
                    'platform': platform.system(), 'model': 'gpt-6.1-sol', 'effort': 'medium', 'toolkit': h.toolkit(),
                    'manifest_sha256': base.sha(h.MANIFEST)}
            path = root / 'plan.json'
            h.write_new(path, plan)
            real_check_output = subprocess.check_output
            def version_probe(argv, **kwargs):
                return 'codex-cli 0.160.0\n' if argv[0] == str(cli) else real_check_output(argv, **kwargs)
            with mock.patch.object(base, 'prepared_source_identity', return_value=plan['source']), \
                    mock.patch.object(base, 'runtime', return_value='digest'), \
                    mock.patch.object(base.subprocess, 'check_output', side_effect=version_probe):
                self.assertEqual(h.preflight(path, root / 'output'), plan)
                self.assertEqual(h.preflight(path, root / 'output'), plan)
                self.assertTrue((root / 'output.preflight-plan.json').is_file())
                (root / 'output').mkdir()
                with self.assertRaises(ValueError):
                    h.preflight(path, root / 'output')
            cli.write_text('drift')
            with self.assertRaises(ValueError):
                h.preflight(path, root / 'different-output')

    def test_base_compaction_receipt_missing_raw_journal_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                h.verify_stop_capture(Path(tmp), {}, {'status': 'passed'})


if __name__ == '__main__':
    unittest.main()
