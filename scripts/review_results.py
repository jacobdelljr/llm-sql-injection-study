"""Create a non-pass review worksheet or validate completed adjudications."""
import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.runner import sha256, write_json

FIELDS = ['run_id', 'case_id', 'automated_outcome', 'evidence', 'decision',
          'reviewer', 'reviewed_utc', 'source_location', 'reproduction', 'notes']
DECISIONS = {'confirmed_injection', 'functional_failure', 'harness_problem', 'unresolved', 'no_demonstrated_injection'}


def expected_rows(evaluation):
    manifest = json.loads((evaluation / 'manifest.json').read_text())
    rows = []
    for job in manifest['jobs']:
        data = json.loads((evaluation / 'details' / (job['run_id'] + '.json')).read_text())
        observations = [{'case_id': '__functional__', **data['functional']}, *data['security']]
        for case in observations:
            if case['outcome'] != 'pass':
                rows.append({'run_id': job['run_id'], 'case_id': case['case_id'],
                             'automated_outcome': case['outcome'], 'evidence': case.get('evidence', ''),
                             'decision': 'pending'})
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evaluation', type=Path, required=True)
    p.add_argument('--reviews', type=Path, required=True)
    p.add_argument('--summary', type=Path, help='validate existing worksheet and save adjudication summary')
    args = p.parse_args()
    expected = expected_rows(args.evaluation)
    if not args.summary:
        args.reviews.parent.mkdir(parents=True, exist_ok=True)
        with args.reviews.open('x', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(expected)
        print(f'Created {len(expected)} review rows; automated scores unchanged.')
        return
    with args.reviews.open(newline='', encoding='utf-8-sig') as stream:
        reviewed = list(csv.DictReader(stream))
    key = lambda r: (r['run_id'], r['case_id'])
    originals = {key(r): r for r in expected}
    if len(reviewed) != len(originals) or {key(r) for r in reviewed} != set(originals):
        p.error('worksheet must contain each expected non-pass exactly once')
    for row in reviewed:
        if any(row[k] != originals[key(row)][k] for k in ('automated_outcome', 'evidence')):
            p.error('original automated evidence was edited')
        if row['decision'] not in DECISIONS or not all(row.get(k, '').strip() for k in ('reviewer', 'reviewed_utc', 'notes')):
            p.error('each row needs a valid decision, reviewer, UTC date and notes')
        if row['decision'] == 'confirmed_injection' and (row['case_id'] == '__functional__' or
                not all(row.get(k, '').strip() for k in ('source_location', 'reproduction'))):
            p.error('confirmed injection requires a security case, source location and reproduction evidence')
    manifest = json.loads((args.evaluation / 'manifest.json').read_text())
    eligible = set()
    for job in manifest['jobs']:
        data = json.loads((args.evaluation / 'details' / (job['run_id'] + '.json')).read_text())
        if data['functional']['outcome'] == 'pass':
            eligible.add(job['run_id'])
    confirmed = {r['run_id'] for r in reviewed if r['decision'] == 'confirmed_injection'}
    if args.summary.exists():
        p.error('choose a new summary path')
    write_json(args.summary, {'review_sha256': sha256(args.reviews.read_bytes()),
        'manifest_sha256': sha256((args.evaluation / 'manifest.json').read_bytes()),
        'decisions': dict(Counter(r['decision'] for r in reviewed)),
        'functionally_passing_denominator': len(eligible),
        'confirmed_injection_among_functional_passes': len(confirmed & eligible),
        'confirmed_injection_among_other_programs': len(confirmed - eligible),
        'harness_problem_present': any(r['decision'] == 'harness_problem' for r in reviewed),
        'unresolved_present': any(r['decision'] == 'unresolved' for r in reviewed),
        'primary_automated_scores_unchanged': True})
    print('Adjudications validated. Automated results preserved.')


if __name__ == '__main__':
    main()
