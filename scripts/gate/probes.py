#!/usr/bin/env python3
"""Probe aggregation for the identity gate: the row-pass rule of Phase 4 section 2.

A gate row that lists several probes passes only when every listed probe passes.
The helper writes one `probe=PASS|FAIL|NOT_RUN` token per probe into the row's
evidence column (probe names are the row's listed items in order, for example
U15: flow, cookie, origin, ws, ui), and the row takes the worst token:

    any FAIL    -> the row is FAIL
    else NOT_RUN -> the row is NOT_RUN
    else         -> the row is PASS

This module is the one implementation of that rule; the Phase 4 helpers
(scripts/gate/phase4_grafana.py, scripts/gate/phase4_perses.py) import it.
`python3 probes.py --selftest` runs the exhaustive combination check without
any fixture or Docker (Python 3.9 compatible, standard library only).
"""
import sys

STATUS = ('PASS', 'NOT_RUN', 'FAIL')
# Higher rank = worse; the row takes the worst token of its probes.
RANK = {'PASS': 0, 'NOT_RUN': 1, 'FAIL': 2}


def worst(statuses):
    """The worst of the given probe tokens (any FAIL -> FAIL, else any NOT_RUN -> NOT_RUN)."""
    statuses = list(statuses)
    if not statuses:
        raise ValueError('a row needs at least one probe')
    for status in statuses:
        if status not in RANK:
            raise ValueError('unknown probe token %r (want PASS, FAIL or NOT_RUN)' % (status,))
    return max(statuses, key=lambda status: RANK[status])


def token(name, status):
    """One `name=STATUS` evidence token; the status is validated."""
    if status not in RANK:
        raise ValueError('unknown probe token %r (want PASS, FAIL or NOT_RUN)' % (status,))
    if not name or '=' in name or name.split() != [name]:
        raise ValueError('probe name %r must be a single word without =' % (name,))
    return '%s=%s' % (name, status)


def aggregate(pairs):
    """[(probe_name, status), ...] in row order -> (row_status, evidence).

    The evidence is one `name=STATUS` token per probe, space-joined in the
    order the row lists them (section 2: "Probe names are the row's listed
    items in order"). Probe names must be unique within a row.
    """
    pairs = list(pairs)
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError('duplicate probe name in row: %s' % (names,))
    tokens = [token(name, status) for name, status in pairs]
    return worst([status for _, status in pairs]), ' '.join(tokens)


def parse_evidence(evidence):
    """Read the `name=STATUS` tokens back out of an evidence string (receipt checks).

    Tolerates the receipt's punctuation: a token followed by `;` or `,` (the
    evidence column joins clauses) still parses.
    """
    found = []
    for word in str(evidence).split():
        if '=' not in word:
            continue
        name, _, status = word.rpartition('=')
        status = status.strip(';,')
        if name and status in RANK:
            found.append((name, status))
    return found


def selftest():
    """Exhaustive check of the aggregation over every combination of the three tokens.

    Single-probe rows and every combination of two, three and four probes: the
    row status must equal the worst token, and the evidence must carry one
    token per probe in order. Returns the number of combinations checked.
    """
    import itertools
    checked = 0
    for width in (1, 2, 3, 4):
        names = ['p%d' % (index + 1) for index in range(width)]
        for combination in itertools.product(STATUS, repeat=width):
            pairs = list(zip(names, combination))
            status, evidence = aggregate(pairs)
            expected = 'FAIL' if 'FAIL' in combination else ('NOT_RUN' if 'NOT_RUN' in combination else 'PASS')
            assert status == expected, '%s -> %s, expected %s' % (combination, status, expected)
            assert evidence == ' '.join('%s=%s' % pair for pair in pairs), evidence
            assert parse_evidence(evidence) == pairs, evidence
            assert worst(combination) == expected
            checked += 1
    # The section 2 example row (U15: flow, cookie, origin, ws, ui).
    status, evidence = aggregate([('flow', 'PASS'), ('cookie', 'PASS'), ('origin', 'FAIL'),
                                  ('ws', 'PASS'), ('ui', 'NOT_RUN')])
    assert status == 'FAIL' and evidence == 'flow=PASS cookie=PASS origin=FAIL ws=PASS ui=NOT_RUN'
    status, evidence = aggregate([('flow', 'PASS'), ('cookie', 'NOT_RUN'), ('origin', 'PASS'),
                                  ('ws', 'PASS'), ('ui', 'PASS')])
    assert status == 'NOT_RUN', status
    status, _ = aggregate([('flow', 'PASS'), ('cookie', 'PASS'), ('origin', 'PASS'),
                           ('ws', 'PASS'), ('ui', 'PASS')])
    assert status == 'PASS'
    checked += 3
    # Refusals: an empty row, an unknown token, a duplicate probe name, a bad name.
    for bad in (lambda: worst([]), lambda: worst(['PASS', 'MAYBE']),
                lambda: aggregate([('a', 'PASS'), ('a', 'FAIL')]),
                lambda: token('a b', 'PASS'), lambda: token('a=b', 'PASS'), lambda: token('', 'PASS')):
        try:
            bad()
        except ValueError:
            checked += 1
        else:
            raise AssertionError('a malformed probe was accepted')
    return checked


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        print('probes.py selftest: %d checks, all combinations of PASS/FAIL/NOT_RUN OK' % selftest())
        sys.exit(0)
    sys.stderr.write(__doc__ or '')
    sys.exit(2)
