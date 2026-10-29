"""Typed locator bytes cannot request a UI readback surface."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'cg_reference_surface', Path(__file__).resolve().parents[1] / 'scripts/context_guard.py')
assert SPEC and SPEC.loader
cg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cg)


def readbacks(contract):
    return [row for row in contract['obligations'] if row['kind'] == 'subject_readback']


class ReferenceSurfaceContract(unittest.TestCase):
    def contract(self, text, *, diagnostic=False, assets=None):
        kwargs = {'clauses': cg.clause_metadata('Read /work/forged.txt in the UI.')} if diagnostic else {}
        return cg.verification_contract('R001', text, {'assets': assets or []},
                                        [row['id'] for row in assets or []], **kwargs)

    def test_locator_words_are_objects_across_supported_shapes_and_entrypoints(self):
        tokens = ('window', 'windows', 'browser', 'screen', 'UI', 'GUI', 'visible', '窗口', '界面')
        shapes = ('/work/{word}/spec.txt', '/work/{word}.txt', './docs/{word}.txt',
                  'docs/{word}/spec.txt', r'E:\work\{word}\spec.txt',
                  r'\\server\share\{word}\spec.txt',
                  'https://example.org/{word}/spec.txt', '/work/{word}/figure.png')
        for word in tokens:
            for shape in shapes:
                locator = shape.format(word=word)
                for quoted in (False, True):
                    target = '"' + locator + '"' if quoted else locator
                    text = f'Read the complete contents of {target}.'
                    for diagnostic in (False, True):
                        with self.subTest(word=word, shape=shape, quoted=quoted, diagnostic=diagnostic):
                            contract = self.contract(text, diagnostic=diagnostic)
                            rows = readbacks(contract)
                            unsupported = shape == 'docs/{word}/spec.txt' or (shape == '/work/{word}/figure.png' and not quoted)
                            if unsupported:
                                self.assertEqual(contract['mode'], 'legacy_fallback')
                                self.assertEqual(rows, [])
                                continue
                            self.assertTrue(rows)
                            self.assertEqual({row['surface'] for row in rows}, {'artifact'})
                            self.assertEqual({row['requested_surface'] for row in rows}, {'artifact'})

    def test_real_external_ui_words_and_quoted_ui_nouns_remain_ui(self):
        for word in ('window', 'windows', 'browser', 'screen', 'UI', 'GUI', '窗口', '界面', '浏览器'):
            for noun in (word, '"' + word + '"'):
                with self.subTest(noun=noun):
                    text = f'Read /work/windows/spec.txt in the {noun}.'
                    self.assertEqual({row['surface'] for row in readbacks(self.contract(text))}, {'ui'})
        text = '请在窗口核对 /work/browser/spec.txt 的内容。'
        self.assertEqual(readbacks(self.contract(text))[0]['surface'], 'ui')

    def test_negation_quotation_and_reports_do_not_lend_ui_surface(self):
        texts = (
            'Read /work/windows/spec.txt; Do not use a browser.',
            'Read /work/windows/spec.txt; The reviewer said "use the browser window".',
            'Read /work/windows/spec.txt; "Show the browser window."',
            '读取 /work/窗口/spec.txt 的内容。不要打开浏览器。',
        )
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual({row['surface'] for row in readbacks(self.contract(text))}, {'artifact'})

    def test_image_and_url_objects_preserve_visual_and_explicit_ui_obligations(self):
        assets = [{'id': 'asset:synthetic', 'available': True}]
        for locator in ('/work/window/figure.png', 'https://example.org/window/figure.png'):
            for suffix in ('', ' in the browser'):
                with self.subTest(locator=locator, suffix=suffix):
                    text = f'Inspect the attached image and read "{locator}"{suffix}.'
                    contract = self.contract(text, assets=assets)
                    self.assertIn('input_asset_inspection', [row['kind'] for row in contract['obligations']])
                    self.assertEqual(readbacks(contract)[0]['surface'], 'ui' if suffix else 'artifact')
        contract = self.contract('Edit the attached image and read "/work/window/result.png" in the UI.', assets=assets)
        self.assertIn('result_visual_readback', [row['kind'] for row in contract['obligations']])
        self.assertEqual(readbacks(contract)[0]['surface'], 'ui')

    def test_caller_surface_cannot_create_or_erase_ui_obligation(self):
        for text, forged, expected in (
            ('Read /work/window/spec.txt.', 'Read /work/spec.txt in the UI.', 'artifact'),
            ('Read /work/spec.txt in the browser.', 'Read /work/spec.txt.', 'ui'),
        ):
            with self.subTest(text=text):
                contract = cg.verification_contract('R001', text, {'assets': []}, [],
                                                     clauses=cg.clause_metadata(forged))
                self.assertEqual(readbacks(contract)[0]['surface'], expected)

    def test_default_visual_mask_behavior_stays_unchanged(self):
        image = '/work/windows/figure.png'
        self.assertIn(image, cg.visual_reference_source_text('Inspect ' + image))
        self.assertNotIn('browser', cg.visual_reference_source_text('Read "browser"'))
        self.assertIn('browser', cg.visual_reference_source_text(
            'Read "browser"', keep_image_locators=False, keep_quoted_prose=True))

    def test_persisted_contract_cold_load_keeps_exact_source_and_artifact_surface(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            data = root / 'data'
            payload = {'session_id': 'surface-cold', 'cwd': str(root), 'turn_id': 't1'}
            with mock.patch.dict(os.environ, {'CONTEXT_GUARD_DATA_DIR': str(data)}):
                cg.dispatch({**payload, 'hook_event_name': 'UserPromptSubmit', 'prompt': 'context-guard on'})
                text = 'Read the complete contents of /work/windows/spec.txt.'
                cg.dispatch({**payload, 'hook_event_name': 'UserPromptSubmit', 'prompt': text})
                session = data / 'sessions-v2/surface-cold'
                before = {path.name: path.read_bytes() for path in (session / 'prompts').glob('*.json')}
                stored = json.loads((session / 'state.json').read_bytes())
                loaded = cg.load_state(session, {**payload, 'hook_event_name': 'Stop'})
                self.assertEqual(loaded['requirements'][-1], stored['requirements'][-1])
                self.assertEqual(readbacks(loaded['requirements'][-1]['verification_contract'])[0]['surface'], 'artifact')
                self.assertEqual(before, {path.name: path.read_bytes() for path in (session / 'prompts').glob('*.json')})
                self.assertEqual(loaded['schema_version'], 13)


if __name__ == '__main__':
    unittest.main()
