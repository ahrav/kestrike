"""Detect and route model cases, legal witness schedules and local planted controls."""

from pathlib import Path

CONSTANTS = {"BOUND": "7"}
# The case that regenerates the traces `detect_witness_fixtures.py` declares, requires them to equal the committed
# ones and replays them against the detector and arbiter cores, and its ignored test.
WITNESS_REPLAY = 'detect-witness-replay'
WITNESS_REPLAY_TEST = 'failover::detect_route_replay_tests::witness::generated_detect_witness_traces_replay'
WINDOW = 'closeWindow(true, false)'
SUSPECT = [WINDOW] * 3
PROBED = SUSPECT + ['probe("a")', 'probe("b")']
NOMINATE = PROBED + ['nominate("a", ready)']
# Three observed windows, after new-peer grace, whose one heartbeat each reports the sender unhealthy.
DECLARED = ['beat(1, 1, false)', WINDOW, 'beat(2, 1, false)', WINDOW, 'beat(3, 1, false)', WINDOW]
# A window that progressed, two with no heartbeat and one with a healthy flat heartbeat: three stalled windows read
# gray. The prefix admits sequences 0 and 1, so the free scheduler's sequences 2 to 4 each admit a heartbeat after it.
GRAY = ['beat(0, 1, true)', WINDOW, WINDOW, WINDOW, 'beat(1, 1, true)', WINDOW]
PREFIXES = {'declared': DECLARED, 'gray': GRAY}
# The verdict's two-class rule, which the declared mutants rewrite.
GRAY_RULE = 'else if ((p.kind == "Gray" or e.grayVotes) and not(e.second)) "GrayNeedsSecondClass"'
FRAME = '{ g: %s, a: %s, x: %s, bound: %s, dark: %s }'
FAULTS = { 'Bounds': 'boundsValid: false', 'Dwell': 'dwellValid: false', 'StaleSuspicion': 'suspicionFresh: false', 'Time': 'age: -1',
    'ProbeBound': 'roundsValid: false', 'ObserverUnhealthy': 'healthy: false',
    'HolderGrace': 'age: 2', 'SelfSuspect': 'answers: 0', 'Alive': 'alive: true', 'Unknown': 'dead: 1, unknown: true',
    'Quorum': 'distinct: false', 'GrayNeedsSecondClass': 'second: false', 'ClockUntrusted': 'clock: false' }


def receive(a=2, x=1, bound='true', dark='false', g=1):
    return 'receive(' + FRAME % (g, a, x, bound, dark) + ')'


def response(a=2, x=1, g=1):
    return 'response(' + FRAME % (g, a, x, 'true', 'false') + ')'


def recipes(family):
    if family == 'route':
        bound = [receive()]
        candidate = [receive(bound='false')]
        opened = candidate + ['ready(1, 1)']
        conflict = bound + [receive(x=2)]
        return { 'Candidate': [receive(bound='false')], 'Bound': bound,
            'ConflictAB': conflict, 'ConflictBA': [receive(x=2), receive()],
            'Dark': [receive(dark='true')], 'DarkKept': [receive(dark='true'), receive()],
            'DarkBelow': [receive(a=3), receive(dark='true')],
            'Stale': bound + [receive(a=1)], 'Flip': [receive(a=3), receive(g=2, a=1)],
            'Duplicate': bound + bound, 'Request': bound + ['request'],
            'RequestWithheld': conflict + ['request'], 'Accepted': bound + [response()],
            'Rejected': bound + [response(a=1)], 'ConflictExit': conflict + [receive(a=3)],
            'Withdrawn': opened + ['withdraw(1, 2)'], 'WithdrawalOvertaken': candidate + ['ready(1, 2)', 'withdraw(1, 1)'],
            'ReadyOnBound': opened + ['ready(2, 3)'], 'WithdrawalAfterOtherReady': opened + ['ready(2, 3)', 'withdraw(1, 4)'],
            'ReopenedWithdraws': opened + ['ready(2, 2)', 'withdraw(2, 3)'],
            'Rebound': opened + ['withdraw(1, 2)', 'ready(2, 3)'] }
    rows = { 'Heartbeat': ['beat(1, 1, true)'], 'Duplicate': ['beat(1, 1, true)'] * 2,
        'Silent': SUSPECT, 'Gray': ['beat(1, 1, true)', WINDOW, 'beat(2, 1, true)', WINDOW, 'beat(3, 1, true)', WINDOW, 'beat(4, 1, true)', WINDOW],
        'UnknownWindow': ['closeWindow(true, true)'], 'AliveWindow': [WINDOW], 'Gap': ['closeWindow(false, false)'],
        'Probe': PROBED, 'Nominate': NOMINATE, 'Retracked': ['beat(7, 4, true)', 'retrack', 'beat(7, 99, true)'],
        'Declared': DECLARED, 'DeclaredAged': DECLARED + [WINDOW], 'DeclaredDemoted': DECLARED + ['beat(4, 1, true)', WINDOW],
        'GrayPromoted': ['beat(1, 1, true)', WINDOW, 'beat(2, 1, true)', WINDOW, 'beat(3, 1, true)', WINDOW, 'beat(4, 1, true)', WINDOW,
            'beat(5, 1, false)', WINDOW, 'beat(6, 1, false)', WINDOW, 'beat(7, 1, false)', WINDOW],
        'DeclaredNominate': DECLARED + ['probe("a")', 'probe("b")', 'nominate("a", { ...ready, declaredVotes: true, second: false })'],
        'GrayKindDeclaredVotes': ['beat(1, 1, true)', WINDOW, 'beat(2, 1, true)', WINDOW, 'beat(3, 1, true)', WINDOW, 'beat(4, 1, true)', WINDOW,
            'nominate("a", { ...ready, declaredVotes: true, second: false })'],
        'DeclaredKindGrayVotes': DECLARED + ['nominate("a", { ...ready, declaredVotes: true, grayVotes: true, second: false })'],
        # A healthy window, an unhealthy one and a second healthy one after three silent windows.
        'SilentExitAcrossUnhealthy': SUSPECT + ['beat(1, 1, true)', WINDOW, 'beat(2, 1, false)', WINDOW, 'beat(3, 2, true)', WINDOW] }
    for name, fields in FAULTS.items():
        prefix = rows['Gray'] if name == 'GrayNeedsSecondClass' else SUSPECT
        rows[name] = prefix + [f'nominate("a", {{ ...ready, {fields} }})']
    rows['NotSuspect'] = ['nominate("a", ready)']
    return rows


def cases(Case):
    for family in ('detect', 'route'):
        yield Case(f'{family}-typecheck', command='typecheck', family=family)
        yield Case(f'{family}-safety', invariant='safety', family=family)
        yield Case(f'{family}-replay', command='replay', family=family)
        if family == 'detect':
            yield Case(WITNESS_REPLAY, command='replay', family=family)
        for witness, actions in recipes(family).items():
            prop = 'witness' + witness
            extra = ''
            if family == 'detect' and (witness in FAULTS or witness == 'NotSuspect'):
                extra = f'  val {prop} = ev.act == "nominate" and ev.res == "{witness}"\n'
            yield Case(f'{family}-reach-{prop}', family=family, recipe=actions, settings={'BOUND': str(len(actions) + 1)},
                invariant='unreached', expected='violation', extra=extra + f'  val unreached = not({prop})\n')
    yield Case('detect-progress', temporal='progress', family='detect', settings={'BOUND': '100'})
    yield Case('detect-broken-progress', temporal='progress', family='detect', settings={'BOUND': '100'}, expected='violation', mutations=[('), weakFair(probe("b"), ', '), weakFair(probe("a"), ')])
    yield Case('detect-declared-progress', temporal='declaredProgress', family='detect', settings={'BOUND': '100'}, step='declareStep')
    yield Case('detect-broken-declared-progress', temporal='declaredProgress', family='detect', settings={'BOUND': '100'}, step='declareStep',
        expected='violation', mutations=[(GRAY_RULE, GRAY_RULE.replace('p.kind == "Gray" or', 'p.kind == "Gray" or p.kind == "Declared" or'))])
    mutants = [
        # Three healthy flat windows: the third reaches the onset count, where the mutant declares.
        ('detect', 'healthy-flat-window-declares', 'HealthyWindowNeverDeclares', recipes('detect')['Gray'][:6],
            ('pure def declaring(p: Peer): bool = p.seen and not(p.affirmed)', 'pure def declaring(p: Peer): bool = p.seen'),
            ('val kept = if (p.affirmed) 0 else p.declared', 'val kept = p.declared')),
        # Two declaring windows after grace: the mutant starts a declared suspicion one window early.
        ('detect', 'early-declared-onset', 'DeclaredNeedsOnsetCount', DECLARED[:4],
            ('val declares = declaring(p) and declared >= 3', 'val declares = declaring(p) and declared >= 2')),
        # A healthy window and an unhealthy one after three silent windows: the mutant restarts the exit count.
        ('detect', 'unhealthy-window-restarts-silent-exit', 'UnhealthyWindowKeepsSilentExit',
            SUSPECT + ['beat(1, 1, true)', WINDOW, 'beat(2, 1, false)', WINDOW],
            ('val keptExit = if (held == "Silent" and declaring(p)) p.exit else 0', 'val keptExit = 0')),
        ('detect', 'declared-vote-masks-gray', 'GrayNominationHasSecondClass',
            SUSPECT + ['probe("a")', 'probe("b")', 'nominate("a", { ...ready, declaredVotes: true, grayVotes: true, second: false })'],
            (GRAY_RULE, GRAY_RULE.replace('e.grayVotes', '(e.grayVotes and not(e.declaredVotes))'))),
        ('detect', 'stalled-resets-gray', 'GrayPreserved', recipes('detect')['Gray'] + ['beat(5, 1, true)'],
            ('else { ...p, seq: seq, seen: true, affirmed: p.affirmed or healthy, empty: 0,',
             'else { ...p, seq: seq, seen: true, affirmed: p.affirmed or healthy, empty: 0, kind: "Alive",')),
        ('detect', 'gray-exits-on-seen', 'GrayExitNeedsProgress', recipes('detect')['Gray'] + ['beat(5, 1, true)', WINDOW, 'beat(6, 1, true)', WINDOW],
            ('val nonempty = if (held == "Gray") p.progressed else if (held == "Declared") false else p.seen and p.affirmed', 'val nonempty = p.seen')),
        ('route', 'latest-arrival-merge' , 'RouteMonotonic', [receive(), receive(a=1)],
            ('else if (below({ g: f.g, a: f.a }, { g: old.g, a: old.a })) old', 'else if (below({ g: f.g, a: f.a }, { g: old.g, a: old.a })) { g: f.g, a: f.a, x: f.x, kind: "Bound" }')),
        ('route', 'accept-below-high-water', 'RouteMonotonic', [receive(), response(a=1)],
            ('f.g == h.g and f.a == h.a and f.x == h.x', 'f.g == h.g and f.a <= h.a and f.x == h.x')),
        ('route', 'order-on-epoch-alone', 'RouteMonotonic', [receive(g=2, a=1), receive(a=3)],
            ('pure def below(f: { g: int, a: int }, h: { g: int, a: int }): bool = f.g < h.g or (f.g == h.g and f.a < h.a)',
             'pure def below(f: { g: int, a: int }, h: { g: int, a: int }): bool = f.a < h.a')),
        ('route', 'retired-generation-rebinds', 'RouteMonotonic', [receive(dark='true'), receive(a=3)],
            ('    if (old.kind == "Dark" and f.g <= old.g) old\n    else if', '    if')),
        ('route', 'stale-retirement-darkens', 'RouteMonotonic', [receive(g=2, a=1), receive(a=3, dark='true')],
            ('else if (below({ g: f.g, a: f.a }, { g: old.g, a: old.a })) old',
             'else if (below({ g: f.g, a: f.a }, { g: old.g, a: old.a })) (if (f.dark) { ...old, kind: "Dark" } else old)')),
        ('route', 'lower-retirement-ignored', 'RouteMonotonic', [receive(a=3), receive(dark='true')],
            ('    else if (f.dark and f.g == old.g) { g: f.g, a: if (f.a > old.a) f.a else old.a, x: 0, kind: "Dark" }\n', '')),
        ('route', 'dark-absorbs-later-generations', 'RouteMonotonic', [receive(dark='true'), receive(g=2, a=1, dark='true')],
            ('    if (old.kind == "Dark" and f.g <= old.g) old\n', '    if (old.kind == "Dark") old\n')),
        ('route', 'dark-sends-requests', 'RouteMonotonic', [receive(dark='true'), 'request'],
            ('sent: Set("Candidate", "Bound").contains(hw.kind)', 'sent: Set("Candidate", "Bound", "Dark").contains(hw.kind)')),
        ('route', 'candidate-keeps-any-binding', 'RouteMonotonic', [receive(), receive(a=3, bound='false')],
            ('else if (tie and old.kind == "Bound") "Bound"', 'else if (old.kind == "Bound") "Bound"')),
        ('route', 'overtaken-withdrawal-unbinds', 'WithdrawalOrdered', [receive(bound='false'), 'ready(1, 2)', 'withdraw(1, 1)'],
            ('val ordered = newest and s == binder', 'val ordered = s == binder')),
        ('route', 'withdrawal-ignores-binder', 'WithdrawalOrdered', [receive(bound='false'), 'ready(1, 1)', 'ready(2, 3)', 'withdraw(1, 2)'],
            ('val ordered = newest and s == binder', 'val ordered = newest')),
        ('route', 'ready-on-bound-keeps-binder', 'WithdrawalOrdered', [receive(bound='false'), 'ready(1, 1)', 'ready(2, 3)', 'withdraw(1, 2)'],
            ("turn' = turn + 1, binder' = s,", "turn' = turn + 1, binder' = if (binds(hw, merged)) s else binder,")),
    ]
    for family, name, prop, actions, *mutation in mutants:
        yield Case(f'{family}-mutant-{name}', family=family, invariant=prop, expected='violation', recipe=actions,
            settings={'BOUND': str(len(actions) + 1)}, mutations=mutation)
    # The free scheduler's safety search from a declared and from a gray peer, past the seven-turn bound's reach.
    for name, prefix in PREFIXES.items():
        yield Case(f'detect-safety-after-{name}', invariant='safety', family='detect', step='prefixed',
            settings={'BOUND': str(len(prefix) + FREE)}, extra=prefixed(prefix))
        # Each prefix ends at a window close, so a later close of a window that admitted a heartbeat shows the free
        # scheduler admits a heartbeat after the prefix.
        yield Case(f'detect-reach-heartbeat-after-{name}', invariant='unreached', family='detect', step='prefixed',
            expected='violation', settings={'BOUND': str(len(prefix) + FREE)}, after=len(prefix) + 1,
            extra=prefixed(prefix) + f'  val unreached = not(turn > {len(prefix)} and ev.act == "window" and prior.seen)\n')
    yield Case('detect-mutant-declared-kept-on-healthy', invariant='HealthyWindowNeverDeclares', family='detect',
        step='prefixed', expected='violation', settings={'BOUND': str(len(DECLARED) + FREE)}, extra=prefixed(DECLARED),
        after=len(DECLARED), mutations=[('val held = if (p.kind == "Declared" and p.affirmed) "Gray" else p.kind', 'val held = p.kind')])


# Free scheduler turns after each prefix of the prefixed safety cases.
FREE = 3


def prefixed(prefix):
    """An instance action that takes `prefix` in order and then the model's free `step`."""
    picks = {}
    for i, action in enumerate(prefix):
        picks.setdefault(action, []).append(str(i))
    return ('  action prefixed = any {\n' + ''.join(f'    all {{ Set({", ".join(indices)}).contains(turn), {action} }},\n'
        for action, indices in picks.items()) + f'    all {{ turn >= {len(prefix)}, step }},\n  }}\n')


def inputs(case, source):
    filename = case.family + '.qnt'
    text = (source / filename).read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f'{case.name}: mutation target is not unique')
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        picks = {}
        for i, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(i))
        extra += '  action recipe = any {\n' + ''.join(f'    all {{ Set({", ".join(indices)}).contains(turn), {action} }},\n' for action, indices in picks.items()) + '  }\n'
    bound = case.settings.get('BOUND', CONSTANTS['BOUND'])
    return {filename: text, 'case.qnt': f'module coreCase {{\n  import {case.family}(BOUND = {bound}).* from "./{case.family}"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == 'replay':
        test = WITNESS_REPLAY_TEST if case.name == WITNESS_REPLAY else f'failover::detect_route_replay_tests::generated_{case.family}_traces_replay'
        return ['cargo', 'test', '-p', 'kestrike', '--lib', '--', '--ignored', '--exact', test, '--nocapture']
    if case.command == 'typecheck':
        return [quint, 'typecheck', case.family + '.qnt']
    prop = ['--temporal', case.temporal] if case.temporal else ['--invariant', case.invariant]
    return [quint, 'verify', 'case.qnt', '--main', 'coreCase', '--server-endpoint', f'127.0.0.1:{port}',
        '--backend', 'tlc', '--tlc-config', str(directory / 'tlc.json'), *prop] + (['--step', 'recipe'] if case.recipe else ['--step', case.step] if case.step else ['--step', 'fixedStep'] if case.temporal else [])


def fixture_recipes(family):
    if family == 'detect':
        return {
            'incident': NOMINATE + ['nominate("a", { ...ready, answers: 0 })', 'nominate("b", ready)', 'nominate("b", { ...ready, clock: false })', 'beat(7, 4, true)', 'retrack', 'beat(7, 99, true)'] + SUSPECT
                + [WINDOW, 'nominate("a", ready)', 'probe("a")', 'probe("b")', 'nominate("a", { ...ready, observation: 2 })'],
            'gray': recipes('detect')['Gray'] + ['beat(5, 1, true)', WINDOW, 'closeWindow(false, false)', 'beat(5, 1, true)', WINDOW, 'beat(6, 2, true)', WINDOW, 'beat(7, 3, true)', WINDOW],
        }
    return {
        'conflict_ab': [receive(), receive(x=2), 'request', response(), receive(), receive(a=3), receive(a=1), receive(a=3), response(), receive(a=3, dark='true'), 'request', receive(g=2, a=1), response(g=2, a=1),
            receive(a=3), receive(a=3, dark='true'), response(g=2, a=1), receive(g=2, a=3), receive(g=2, a=2, dark='true'), 'request'],
        'conflict_ba': [receive(x=2), receive(), 'request', response(x=2), receive(a=3, bound='false'), 'request', receive(a=3), response(a=3), receive(g=2, a=1, dark='true'), receive(g=2, a=1),
            'request', receive(g=2, a=3, x=2), 'request', receive(g=3, a=1, x=2, dark='true'), receive(g=3, a=2, x=2), receive(g=2, a=3), 'request'],
    }


def fixtures():
    """Each committed core trace of both families: its model and the recipe it records under `#meta.cores`."""
    return {name: (family + '.qnt', {'recipe': recipe})
            for family in ('detect', 'route') for name, recipe in fixture_recipes(family).items()}


def generate(quint, family, output):
    import hashlib
    import json
    import subprocess
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    for name, actions in fixture_recipes(family).items():
        case = SimpleNamespace(name=name, family=family, mutations=[], extra='', recipe=actions, settings={'BOUND': str(len(actions) + 1)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + '.itf.json')
        subprocess.run([quint, 'run', 'case.qnt', '--main', 'coreCase', '--step', 'recipe', '--backend', 'typescript', '--mbt', '--invariant', 'safety', '--seed', '0x1169', '--max-samples', '1', '--max-steps', str(len(actions) + 1), '--n-traces', '1', '--out-itf', str(trace)], cwd=directory, check=True, timeout=60)
        try:
            data = json.loads(trace.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f'{name}: Quint wrote no readable trace: {error}') from error
        if len(data['states']) != len(actions) + 1:
            raise ValueError(f'{name}: recipe stopped before its final action')
        data['#meta']['cores'] = {'recipe': actions, 'model_sha256': hashlib.sha256((source / (family + '.qnt')).read_bytes()).hexdigest()}
        trace.write_text(json.dumps(data, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quint', required=True)
    parser.add_argument('--family', choices=['detect', 'route'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.family, args.output.resolve())
