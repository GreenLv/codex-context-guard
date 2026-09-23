"""Zero-model public entrypoints, with actual file readback and fail-first controls."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.validation import acceptance_evidence as receipts
from tools.validation import execution_probe, native_acceptance


class ToolEntrypointTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def test_bad_batch_blocks_before_codex_or_host_adapter(self):
        manifest=self.root/'batch.json'
        manifest.write_text('{}', encoding='utf-8')
        with patch.object(native_acceptance, 'resolve_executable') as model, self.assertRaises(SystemExit):
            native_acceptance.main(['--repo-root', str(Path.cwd()), '--source-commit', 'a'*40,
                                    '--output', str(self.root/'result.json'), '--batch-manifest', str(manifest)])
        model.assert_not_called()
        self.assertFalse((self.root/'result.json').exists())

    def test_transfer_cli_reads_actual_bytes_and_preserves_receipt(self):
        payload=self.root/'payload'
        payload.write_bytes('原始字节\n'.encode())
        expected=receipts.payload_identity({'payload':payload.read_bytes()})
        request={'operation':'transfer_readback', 'request_id':'r1',
                 'files':[{'name':'payload','path':str(payload)}],
                 'events':[{'request_id':'r1','stage':'accepted','payload':expected}]}
        source=self.root/'input.json'
        source.write_text(json.dumps(request), encoding='utf-8')
        output=self.root/'result.json'
        args=['--input',str(source),'--output',str(output)]
        self.assertEqual(receipts.main(args),0)
        result=json.loads(output.read_text())
        self.assertEqual(result['actual_payload'],expected)
        self.assertEqual(result['status'],'accepted')
        self.assertFalse(result['execution_reported'])
        with self.assertRaises(SystemExit):
            receipts.main(args)
        payload.write_bytes(b'changed')
        self.assertEqual(receipts.main(['--input',str(source),'--output',str(self.root/'changed.json')]),0)
        self.assertEqual(json.loads((self.root/'changed.json').read_text())['status'],'unknown')

    def test_actual_probe_checks_own_writes_and_never_claims_other_route(self):
        witness=self.root/'witness'
        witness.write_bytes(b'input')
        result=execution_probe.probe(Path.cwd(), self.root, [witness])
        self.assertTrue(result['checks']['fixture_write_read_cleanup'])
        self.assertTrue(result['checks']['witnesses_readable'])
        self.assertFalse(result['checks']['git_initial_commit_readable'])
        self.assertEqual(result['other_route_permissions'],'unknown')
        self.assertEqual(list(self.root.glob('.cg-probe-*')),[])
        mismatch=execution_probe.probe(self.root/'different-cwd',self.root,[witness])
        self.assertFalse(mismatch['checks']['fixture_write_read_cleanup'])
        with patch.object(execution_probe.tempfile,'TemporaryDirectory',side_effect=PermissionError):
            denied=execution_probe.probe(Path.cwd(),self.root,[witness])
        self.assertFalse(denied['checks']['fixture_write_read_cleanup'])

    def test_valid_batch_preflight_binds_runtime_and_never_installs(self):
        import hashlib
        import subprocess

        from tools.validation import batch_preflight
        repo=Path.cwd()
        commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
        artifact=self.root/'input.txt'
        artifact.write_bytes(b'preflight input')
        digest=native_acceptance.runtime_digest(native_acceptance.load_manager(repo),repo)
        manifest={'schema':batch_preflight.SCHEMA,'source_commit':commit,
                  'runtime_tree_sha256':digest,'plan_sha256':'a'*64,
                  'fixtures':[{'repo':str(repo),'initial_head':commit,'changed_paths':['module.py']}],
                  'sessions':[{'id':'one','role':'git_trust'},{'id':'two','role':'continuity'}],
                  'inputs':[{'role':role,'path':str(artifact),'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()}
                            for role in sorted(batch_preflight.INPUT_ROLES)],
                  'expectations':[{'contract':'INV-07','kind':'current_contract','assertion':'ordinary_tools_are_host_owned'}],
                  'budget':{'turns':1,'turn_seconds':1,'startup':1,'compact':1,'cleanup':1},
                  'permission_route':'unavailable'}
        manifest['driver_timeouts']=batch_preflight.wait_budget(**manifest['budget'])
        source=self.root/'batch.json'
        source.write_text(json.dumps(manifest),encoding='utf-8')
        args=['--repo-root',str(repo),'--source-commit',commit,'--output',str(self.root/'native.json'),
              '--batch-manifest',str(source),'--preflight']
        with patch.object(native_acceptance,'verify_exact_source'), \
             patch.object(native_acceptance,'resolve_executable',return_value='codex'), \
             patch.object(native_acceptance,'run',return_value=subprocess.CompletedProcess([],0,'https://github.com/example/repo.git','')), \
             patch.object(native_acceptance,'portable_acceptance') as install:
            self.assertEqual(native_acceptance.main(args),0)
            install.assert_not_called()
        self.assertFalse((self.root/'native.json').exists())
        manifest['runtime_tree_sha256']='b'*64
        source.write_text(json.dumps(manifest),encoding='utf-8')
        with patch.object(native_acceptance,'resolve_executable') as model,self.assertRaises(SystemExit):
            native_acceptance.main(args)
        model.assert_not_called()
