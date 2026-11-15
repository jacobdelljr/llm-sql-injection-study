import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from scripts.collect_experiment import collect
from evaluation.docker_backend import command


class CollectionTests(unittest.TestCase):
    def run_fake(self, outcomes, directory):
        calls = []
        def create(**kwargs):
            calls.append(kwargs)
            item = outcomes.pop(0)
            if isinstance(item, Exception):
                raise item
            return SimpleNamespace(model_dump=lambda **kw: item, _request_id='request-test')
        client = SimpleNamespace(messages=SimpleNamespace(create=create))
        jobs = [{'run_id': 'test', 'effort': 'low', 'prompt': 'fixed prompt'}]
        collect(jobs, directory, {'model': 'test-model', 'max_tokens': 10, 'max_attempts': 3}, client, sleep=lambda _: None)
        return calls

    def test_refusal_is_saved_and_not_retried_or_replaced(self):
        with tempfile.TemporaryDirectory() as path:
            path = Path(path)
            calls = self.run_fake([{'stop_reason': 'refusal', 'content': []}], path)
            self.assertEqual(len(calls), 1)
            self.assertEqual(self.run_fake([], path), [])
            self.assertEqual(json.loads((path / 'responses/test.json').read_text())['stop_reason'], 'refusal')

    def test_service_retries_are_journaled(self):
        error = RuntimeError('synthetic')
        error.status_code = 429
        with tempfile.TemporaryDirectory() as path:
            path = Path(path)
            calls = self.run_fake([error, {'stop_reason': 'max_tokens', 'content': []}], path)
            self.assertEqual(len(calls), 2)
            state = json.loads((path / 'attempts/test.json').read_text())
            self.assertEqual([a['status'] for a in state['attempts']], ['service_error', 'received'])

    def test_interrupted_send_is_not_silently_repeated(self):
        with tempfile.TemporaryDirectory() as path:
            path = Path(path)
            (path / 'attempts').mkdir()
            (path / 'attempts/test.json').write_text(json.dumps({'attempts': [{'status': 'sending'}]}))
            with self.assertRaises(RuntimeError):
                self.run_fake([], path)

    def test_container_has_no_mounts_or_passed_environment(self):
        args = command('sha256:' + 'a' * 64, 'test')
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--memory=256m'):
            self.assertIn(flag, args)
        self.assertNotIn('-v', args)
        self.assertNotIn('--mount', args)
        self.assertNotIn('-e', args)
        with self.assertRaises(ValueError):
            command('mutable:tag', 'test')


if __name__ == '__main__':
    unittest.main()
