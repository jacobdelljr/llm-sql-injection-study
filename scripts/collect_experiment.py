"""Collect the fixed schedule. No dotenv loading and no generated-code execution."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_evaluation import read_jobs
from evaluation.runner import sha256, write_json, evaluator_hash


def now():
    return datetime.now(timezone.utc).isoformat()


def collect(jobs, out, settings, client, sleep=time.sleep):
    """Journal before sending. Interrupted in-flight requests are never silently repeated."""
    for job in jobs:
        run_id = job['run_id']
        response_path = out / 'responses' / (run_id + '.json')
        state_path = out / 'attempts' / (run_id + '.json')
        state = json.loads(state_path.read_text()) if state_path.exists() else {'job': job, 'attempts': []}
        if response_path.exists():
            if not state['attempts']:
                raise RuntimeError(f'{run_id}: response has no attempt provenance')
            digest = sha256(response_path.read_bytes())
            previous = state['attempts'][-1]
            if previous.get('response_sha256') and previous['response_sha256'] != digest:
                raise RuntimeError(f'{run_id}: saved response changed')
            if previous['status'] == 'sending':
                raw = json.loads(response_path.read_text())
                previous.update(status='received', recovered_utc=now(), response_sha256=digest,
                                response_id=raw.get('id'), returned_model=raw.get('model'),
                                stop_reason=raw.get('stop_reason'), usage=raw.get('usage'))
                state['terminal'] = True
                write_json(state_path, state)
            print('saved:', run_id, flush=True)
            continue
        if state.get('terminal'):
            continue
        if state['attempts'] and state['attempts'][-1]['status'] == 'sending':
            raise RuntimeError(f'{run_id}: interrupted request with unknown billing/outcome; inspect attempt journal before continuing')
        while len(state['attempts']) < settings['max_attempts']:
            attempt = {'started_utc': now(), 'status': 'sending', 'number': len(state['attempts']) + 1}
            state['attempts'].append(attempt)
            write_json(state_path, state)
            try:
                response = client.messages.create(model=settings['model'], max_tokens=settings['max_tokens'],
                    thinking={'type': 'adaptive'}, output_config={'effort': job['effort']},
                    messages=[{'role': 'user', 'content': job['prompt']}])
            except Exception as error:
                # Do not store exception bodies, which can contain request headers.
                status = getattr(error, 'status_code', None)
                retryable = status in (408, 409, 429) or (isinstance(status, int) and status >= 500)
                retryable |= type(error).__name__ in ('APIConnectionError', 'APITimeoutError')
                attempt.update(status='service_error', ended_utc=now(), error_type=type(error).__name__,
                               http_status=status, request_id=getattr(error, 'request_id', None))
                state['terminal'] = not retryable or len(state['attempts']) >= settings['max_attempts']
                write_json(state_path, state)
                if not retryable:
                    raise RuntimeError(f'Collection stopped on {type(error).__name__}, HTTP {status}; see journal') from None
                if not state['terminal']:
                    sleep(2 ** len(state['attempts']))
                continue
            raw = response.model_dump(mode='json')
            write_json(response_path, raw)
            attempt.update(status='received', ended_utc=now(), request_id=getattr(response, '_request_id', None),
                           response_id=raw.get('id'), returned_model=raw.get('model'),
                           stop_reason=raw.get('stop_reason'), usage=raw.get('usage'),
                           response_sha256=sha256(response_path.read_bytes()))
            state['terminal'] = True
            write_json(state_path, state)
            print('collected:', run_id, raw.get('stop_reason'), flush=True)
            break


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--schedule', type=Path, default=ROOT / 'runs/main/schedule.json')
    p.add_argument('--out', type=Path, default=ROOT / 'runs/main/collection')
    p.add_argument('--model', required=True)
    p.add_argument('--max-tokens', type=int, default=4096)
    p.add_argument('--max-attempts', type=int, default=3)
    p.add_argument('--execute', action='store_true', help='send paid requests; default is offline dry run')
    p.add_argument('--controls-report', type=Path)
    p.add_argument('--isolation-report', type=Path)
    args = p.parse_args()
    if args.max_tokens <= 0 or args.max_attempts <= 0:
        p.error('limits must be positive')
    jobs = read_jobs(False, args.schedule)
    if any(not isinstance(j.get('prompt'), str) or not j['prompt'].strip() for j in jobs):
        p.error('every scheduled prompt must be nonempty')
    settings = dict(model=args.model, max_tokens=args.max_tokens, max_attempts=args.max_attempts,
                    thinking='adaptive', request_timeout_seconds=120, backoff='2**attempt seconds',
                    schedule_sha256=sha256(args.schedule.read_bytes()), evaluator_sha256=evaluator_hash(),
                    collector_sha256=sha256(Path(__file__).read_bytes()),
                    sdk_version=importlib.metadata.version('anthropic'))
    print(f'225 scheduled programs; at most {225 * args.max_attempts} attempts; '
          f'{225 * args.max_attempts * args.max_tokens} maximum requested output tokens including retries.')
    if not args.execute:
        print('Dry run: no requests or files written. Confirm model/settings and provider budget before --execute.')
        return
    if not args.controls_report or not args.isolation_report:
        p.error('--execute requires --controls-report and --isolation-report')
    controls = json.loads(args.controls_report.read_text())
    isolation = json.loads(args.isolation_report.read_text())
    if (controls.get('mismatches') != 0 or controls.get('checks') != 137
            or controls.get('evaluator_sha256') != evaluator_hash()
            or not isolation.get('verified') or isolation.get('image') != os.environ.get('SQL_EVAL_IMAGE')):
        p.error('isolation/control reports do not match the selected evaluator and image')
    if any(sha256((ROOT / path).read_bytes()) != digest for path, digest in isolation['files'].items()):
        p.error('source changed since isolation verification')
    settings.update(controls_report_sha256=sha256(args.controls_report.read_bytes()),
                    isolation_report_sha256=sha256(args.isolation_report.read_bytes()),
                    protocol_sha256=sha256((ROOT / 'evaluation_protocol.md').read_bytes()))
    if not os.environ.get('ANTHROPIC_API_KEY'):
        p.error('set ANTHROPIC_API_KEY in this process environment; .env is never loaded')
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = args.out / 'manifest.json'
    if manifest.exists():
        if json.loads(manifest.read_text())['settings'] != settings:
            p.error('frozen settings changed; use the original settings and source')
    elif any(args.out.iterdir()):
        p.error('new collection directory must be empty')
    else:
        write_json(manifest, {'created_utc': now(), 'settings': settings, 'jobs': jobs})
    lock = args.out / '.collector.lock'
    try:
        with lock.open('x') as stream:
            stream.write(str(os.getpid()))
    except FileExistsError:
        p.error('collector lock exists; ensure no collector is running before removing a stale lock')
    try:
        from anthropic import Anthropic
        with Anthropic(max_retries=0, timeout=120) as client:
            collect(jobs, args.out, settings, client)
    finally:
        lock.unlink()


if __name__ == '__main__':
    main()
