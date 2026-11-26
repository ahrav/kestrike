"""Record one trace per replayable detect reach recipe, and an exhausted-then-observed one, for the witness replay.

Each trace runs one legal recipe of `detect_route_check.recipes('detect')`, or the exhausted-then-observed
recipe below, through `quint run --mbt` exactly as `detect_route_check.generate` records the core fixtures:
TypeScript simulator, seed 0x1169, one sample, `BOUND` one above the recipe's length. The trace records its
recipe and the model's digest under `#meta.cores`, which the Rust replay checks before it runs an action.
The `NotSuspect` recipe stays with its reach case: its nomination is issued while the peer reads alive, and
`arbiter::nominate` takes a suspicion, which the Rust replay takes from a preceding dead reading.
"""

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("detect_route_checks", SOURCE / "detect_route_check.py")
detect_route_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect_route_checks)

FIXTURES = 'crates/kestrike/src/failover/detect_witness_fixtures'
EXHAUSTED = 'closeWindow(true, true)'


def witness_recipes():
    """Return each replayed recipe by its fixture name."""
    rows = {name: actions for name, actions in detect_route_checks.recipes('detect').items() if name != 'NotSuspect'}
    # Three exhausted windows read Unknown while their counters advance, so the next observed window reads Silent.
    rows['ExhaustedThenSilent'] = [EXHAUSTED] * 3 + [detect_route_checks.WINDOW]
    return rows


def fixtures():
    """Each committed trace: its model and the recipe it records under `#meta.cores`."""
    return {name: ('detect.qnt', {'recipe': actions}) for name, actions in witness_recipes().items()}


def generate(quint, output):
    for name, actions in witness_recipes().items():
        case = SimpleNamespace(name=name, family='detect', mutations=[], extra='', recipe=actions,
                               settings={'BOUND': str(len(actions) + 1)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in detect_route_checks.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + '.itf.json')
        subprocess.run([quint, 'run', 'case.qnt', '--main', 'coreCase', '--step', 'recipe', '--backend', 'typescript',
                        '--mbt', '--invariant', 'safety', '--seed', '0x1169', '--max-samples', '1',
                        '--max-steps', str(len(actions) + 1), '--n-traces', '1', '--out-itf', str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data['states']) != len(actions) + 1:
            raise ValueError(f'{name}: recipe stopped before its final action')
        data['#meta']['cores'] = {'recipe': actions,
                                  'model_sha256': hashlib.sha256((SOURCE / 'detect.qnt').read_bytes()).hexdigest()}
        trace.write_text(json.dumps(data, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quint', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
