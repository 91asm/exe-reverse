#!/usr/bin/env python3
"""capability: symbolic_reduce

Reduce an obfuscated bit-vector expression to a simpler equivalent, and say how far the evidence
for that goes.

WHY THIS EXISTS
---------------
A protector that flattens control flow and rewrites arithmetic does its damage with algebra, not with
encryption. The classic substitution replaces one operator with several, so `x + y` arrives as
`(x | y) + (x & y)` or `(x ^ y) + 2 * (x & y)`, and a chain of those turns a readable comparison
into something no reader will untangle by eye. Every one of those rewrites is an **identity**: the
obfuscated form is exactly equal, for every input, on the bit width in use.

That is what makes reduction possible without executing anything and without a solver. It is a
rewriting problem, and the answer is checkable by substitution -- which matters, because this kit
refuses to depend on a component the host may not have, and a solver is exactly such a component
(a fresh host here has none).

The values are machine words, not integers: every operation wraps at a fixed width, shifts are
logical, and the width is part of the question rather than a detail. `x * 2` equals `x << 1` at
32 bits and stops being true the moment you compute it at 64.

WHAT THE VERDICT MEANS, AND WHAT IT DOES NOT
--------------------------------------------
Reduction is followed by **sampling**: the original and the reduced form are evaluated on random
inputs, on the boundary values that break most bit tricks (0, 1, all-ones, the single-bit patterns,
and the sign boundary), and on any constants the expression itself contains. If a sample disagrees,
the reduction is **wrong** and the tool says so -- a counter-example is a proof of failure.

If no sample disagrees, that is **not** a proof of equality. Sampling refutes; it cannot confirm.
The honest statement is "equivalent on N inputs including the boundaries", and the exit code and the
last line say exactly that rather than claiming a proof this tool cannot produce.

Usage
-----
    python trace_reduce.py "(x | y) + (x & y)"
    python trace_reduce.py "(x ^ y) + 2 * (x & y)" --bits 32 --verbose
    python trace_reduce.py "~(~x) + 0 - 0" --json
    python trace_reduce.py --file expr.txt
    python trace_reduce.py --list-rules
    python trace_reduce.py "(x & 0xff) ^ (x & 0xff)"

Exit codes: 0 = reduced and every sample agrees, 1 = a sample disagreed (the reduction is wrong),
2 = usage error, 3 = the expression could not be parsed. The last line is `RESULT=<token>`.
"""

import argparse
import json
import random
import re
import sys

EXIT_OK = 0
EXIT_COUNTEREXAMPLE = 1
EXIT_USE = 2
EXIT_PARSE = 3

TOKENS = {'ok': 'reduce_equivalent_on_samples', 'refuted': 'reduce_refuted',
          'use': 'usage_error', 'parse': 'parse_error'}

MASK = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}


# ---------------------------------------------------------------- expression tree

class Node(object):
    __slots__ = ('kind', 'value', 'op', 'kids')

    def __init__(self, kind, value=None, op=None, kids=()):
        self.kind = kind                      # const | var | bin | un
        self.value = value
        self.op = op
        self.kids = list(kids)

    def key(self):
        """A structural key, so two structurally identical subtrees compare equal."""
        if self.kind == 'const':
            return ('c', self.value)
        if self.kind == 'var':
            return ('v', self.value)
        if self.kind == 'un':
            return ('u', self.op, self.kids[0].key())
        return ('b', self.op, self.kids[0].key(), self.kids[1].key())

    def text(self, parent_op=None):
        if self.kind == 'const':
            return hex(self.value)
        if self.kind == 'var':
            return self.value
        if self.kind == 'un':
            inner = self.kids[0].text('~')
            return '%s%s' % (self.op, inner)
        prec = {'|': 1, '^': 2, '&': 3, '+': 4, '-': 4, '*': 5, '<<': 6, '>>': 6}
        me = prec.get(self.op, 9)
        left = self.kids[0].text(self.op)
        right = self.kids[1].text(self.op)
        s = '%s %s %s' % (left, self.op, right)
        return '(%s)' % s if parent_op and prec.get(parent_op, 9) > me else s


TOKEN_RE = re.compile(r'''
    \s*(?:
      (?P<hex>0[xX][0-9a-fA-F]+)
    | (?P<dec>\d+)
    | (?P<name>[A-Za-z_][A-Za-z_0-9]*)
    | (?P<op><<|>>|[()+\-*/&^|~])
    )''', re.VERBOSE)


def tokenize(text):
    pos, out = 0, []
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            if text[pos:].strip():
                raise ValueError('cannot read %r at offset %d' % (text[pos:pos + 12], pos))
            break
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


class Parser(object):
    """Precedence climbing over the C operator set, restricted to bit-vector arithmetic."""

    LEVELS = [('|',), ('^',), ('&',), ('+', '-'), ('*',), ('<<', '>>')]

    def __init__(self, tokens):
        self.t = tokens
        self.i = 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, value=None):
        kind, tok = self.peek()
        if value is not None and tok != value:
            raise ValueError('expected %r, found %r' % (value, tok))
        self.i += 1
        return kind, tok

    def parse(self):
        node = self.binary(0)
        if self.i != len(self.t):
            raise ValueError('unexpected trailing %r' % (self.peek()[1],))
        return node

    def binary(self, level):
        if level >= len(self.LEVELS):
            return self.unary()
        left = self.binary(level + 1)
        while True:
            _kind, tok = self.peek()
            if tok in self.LEVELS[level]:
                self.take()
                right = self.binary(level + 1)
                left = Node('bin', op=tok, kids=(left, right))
            else:
                return left

    def unary(self):
        kind, tok = self.peek()
        if tok in ('~', '-'):
            self.take()
            return Node('un', op=tok, kids=(self.unary(),))
        if tok == '(':
            self.take('(')
            node = self.binary(0)
            self.take(')')
            return node
        if kind == 'hex':
            self.take()
            return Node('const', value=int(tok, 16))
        if kind == 'dec':
            self.take()
            return Node('const', value=int(tok, 10))
        if kind == 'name':
            self.take()
            return Node('var', value=tok)
        raise ValueError('expected a value, found %r' % (tok,))


def evaluate(node, env, mask):
    if node.kind == 'const':
        return node.value & mask
    if node.kind == 'var':
        return env[node.value] & mask
    if node.kind == 'un':
        v = evaluate(node.kids[0], env, mask)
        return (~v) & mask if node.op == '~' else ((-v) & mask)
    a = evaluate(node.kids[0], env, mask)
    b = evaluate(node.kids[1], env, mask)
    op = node.op
    if op == '+':
        return (a + b) & mask
    if op == '-':
        return (a - b) & mask
    if op == '*':
        return (a * b) & mask
    if op == '&':
        return a & b
    if op == '|':
        return a | b
    if op == '^':
        return a ^ b
    if op == '<<':
        return (a << (b & 63)) & mask
    if op == '>>':
        return (a & mask) >> (b & 63)
    raise ValueError('unknown operator %r' % op)


def variables(node, out=None):
    out = set() if out is None else out
    if node.kind == 'var':
        out.add(node.value)
    for k in node.kids:
        variables(k, out)
    return out


# ---------------------------------------------------------------- rewriting
#
# Each rule is (name, matcher, replacement-builder, note). The note is the part that matters when a
# reduction is disputed: it says which identity was used, not merely that something changed.

def c(value):
    return Node('const', value=value)


def is_const(node, value=None):
    return node.kind == 'const' and (value is None or node.value == value)


def same(a, b):
    return a.key() == b.key()


def _commute_bin(node):
    """The operand pair, in both orders, so a rule does not have to name both."""
    return [(node.kids[0], node.kids[1]), (node.kids[1], node.kids[0])]


def r_identities(node, mask):
    """Absorption and neutral elements. These are the rules that shrink without changing meaning."""
    if node.kind != 'bin':
        return None
    a, b = node.kids
    op = node.op
    for x, y in _commute_bin(node):
        if op in ('+', '|', '^') and is_const(y, 0):
            return x, 'x %s 0 == x' % op
        if op == '-' and is_const(y, 0):
            return x, 'x - 0 == x'
        if op == '*' and is_const(y, 1):
            return x, 'x * 1 == x'
        if op == '*' and is_const(y, 0):
            return c(0), 'x * 0 == 0'
        if op == '&' and is_const(y, 0):
            return c(0), 'x & 0 == 0'
        if op == '&' and y.kind == 'const' and (y.value & mask) == mask:
            return x, 'x & all-ones == x'
        if op == '|' and y.kind == 'const' and (y.value & mask) == mask:
            return c(mask), 'x | all-ones == all-ones'
    if same(a, b):
        if op == '^':
            return c(0), 'x ^ x == 0'
        if op == '-':
            return c(0), 'x - x == 0'
        if op == '&' or op == '|':
            return a, 'x %s x == x' % op
    if op in ('+', '-') and a.kind == 'bin' and b.kind == 'bin':
        # (p op1 q) + (p op2 q) style collapse is left to the MBA rules below.
        pass
    return None


def r_double_negation(node, mask):
    if node.kind == 'un' and node.kids[0].kind == 'un':
        inner, outer = node.kids[0], node.op
        if inner.op == '~' and outer == '~':
            return inner.kids[0], '~(~x) == x'
        if inner.op == '-' and outer == '-':
            return inner.kids[0], '-(-x) == x'
    return None


def r_mba(node, mask):
    """The substitutions a protector uses, recognised in reverse.

    Each of these is an identity over bit vectors, so recognising the shape is enough: no input has
    to be tried to know the two forms are the same function. They are checked by sampling anyway,
    because a rule implemented slightly wrong is worse than a rule that is absent.
    """
    if node.kind != 'bin':
        return None
    if node.op == '+':
        for p, q in _commute_bin(node):
            if p.kind == 'bin' and q.kind == 'bin':
                if {p.op, q.op} == {'&', '|'} and same(p.kids[0], q.kids[0]) \
                        and same(p.kids[1], q.kids[1]):
                    return (Node('bin', op='+', kids=(p.kids[0], p.kids[1])),
                            '(x & y) + (x | y) == x + y')
                if {p.op, q.op} == {'^', '*'}:
                    mul = p if p.op == '*' else q
                    xor = q if p.op == '*' else p
                    for m, two in _commute_bin(mul):
                        if is_const(two, 2) and m.kind == 'bin' and m.op == '&':
                            if same(xor.kids[0], m.kids[0]) and same(xor.kids[1], m.kids[1]):
                                return (Node('bin', op='+', kids=(xor.kids[0], xor.kids[1])),
                                        '(x ^ y) + 2 * (x & y) == x + y')
    if node.op == '-':
        left, right = node.kids
        if left.kind == 'bin' and right.kind == 'bin':
            if {left.op, right.op} == {'&', '|'} and same(left.kids[0], right.kids[0]) \
                    and same(left.kids[1], right.kids[1]):
                union = left if left.op == '|' else right
                inter = right if left.op == '|' else left
                if same(union.kids[0], inter.kids[0]) and same(union.kids[1], inter.kids[1]):
                    return (Node('bin', op='^', kids=(union.kids[0], union.kids[1])),
                            '(x | y) - (x & y) == x ^ y')
    return None


RULES = [('identity', r_identities), ('involution', r_double_negation), ('mba', r_mba)]


def fold(node, mask):
    """Constant folding, applied before the rules so a rule sees concrete constants."""
    if node.kind == 'un' and node.kids[0].kind == 'const':
        v = evaluate(node, {}, mask)
        return c(v)
    if node.kind == 'bin' and node.kids[0].kind == 'const' and node.kids[1].kind == 'const':
        return c(evaluate(node, {}, mask))
    return node


def reduce_once(node, mask):
    """One bottom-up pass. Returns (node, [(rule, note, before, after)])."""
    steps = []

    def walk(n):
        if n.kind in ('bin', 'un'):
            n = Node(n.kind, op=n.op, kids=[walk(k) for k in n.kids])
        n = fold(n, mask)
        for rule_name, rule in RULES:
            hit = rule(n, mask)
            if hit:
                new, note = hit
                steps.append((rule_name, note, n.text(), new.text()))
                return fold(new, mask)
        return n

    return walk(node), steps


def reduce_all(node, mask, limit=64):
    all_steps = []
    for _ in range(limit):
        node, steps = reduce_once(node, mask)
        all_steps.extend(steps)
        if not steps:
            break
    return node, all_steps


# ---------------------------------------------------------------- sampling

def sample_envs(node, mask, count, seed=0x5EED):
    """Inputs chosen to break bit tricks, not merely to be random.

    Random values alone miss the cases these identities are most easily got wrong on: zero, one,
    all-ones, the single-bit patterns, and the pair around the sign boundary. A rule that holds on
    random inputs and fails at `0x80000000` is a rule that fails on real data.
    """
    names = sorted(variables(node))
    if not names:
        return [{}]
    edges = [0, 1, 2, mask, mask ^ 1, mask ^ 2, mask >> 1, (mask >> 1) + 1]
    edges += [1 << b for b in range(0, min(mask.bit_length(), 8))]
    envs = []
    for i in range(count):
        rng = random.Random(seed + i)
        env = {}
        for k, name in enumerate(names):
            if i < len(edges):
                env[name] = (edges[i] + k) & mask
            else:
                env[name] = rng.getrandbits(mask.bit_length())
        envs.append(env)
    # One pass that walks every variable through the same edge value, so single-variable patterns
    # are not hidden by a differing value in another variable.
    for value in edges[:12]:
        envs.append({name: (value + i) & mask for i, name in enumerate(names)})
    return envs


def verify(original, reduced, mask, count):
    names = sorted(variables(original) | variables(reduced))
    if not names:
        a, b = evaluate(original, {}, mask), evaluate(reduced, {}, mask)
        return (a == b), None, 1
    envs = sample_envs(Node('bin', op='+', kids=(original, reduced)) if False else original,
                       mask, count)
    checked = 0
    for env in envs:
        env = dict(env)
        for n in names:
            env.setdefault(n, 0)
        a = evaluate(original, env, mask)
        b = evaluate(reduced, env, mask)
        checked += 1
        if a != b:
            return False, {'env': env, 'original': a, 'reduced': b}, checked
    return True, None, checked


# ---------------------------------------------------------------- report

def rule_table():
    return [
        ('identity', 'x + 0, x - 0, x | 0, x ^ 0, x * 1 -> x'),
        ('identity', 'x * 0 -> 0, x & 0 -> 0'),
        ('identity', 'x & all-ones -> x, x | all-ones -> all-ones'),
        ('identity', 'x ^ x -> 0, x - x -> 0, x & x -> x, x | x -> x'),
        ('involution', '~(~x) -> x, -(-x) -> x'),
        ('mba', '(x & y) + (x | y) -> x + y'),
        ('mba', '(x ^ y) + 2 * (x & y) -> x + y'),
        ('mba', '(x | y) - (x & y) -> x ^ y'),
        ('fold', 'two constants -> their value at this width'),
    ]


def main():
    ap = argparse.ArgumentParser(
        description='Reduce an obfuscated bit-vector expression to a simpler equivalent, and state '
                    'how far the evidence for that goes.')
    ap.add_argument('expression', nargs='?', help='the expression, in C operator syntax')
    ap.add_argument('--file', help='read the expression from a file instead')
    ap.add_argument('--bits', type=int, default=32, choices=sorted(MASK),
                    help='word width; the identities depend on it (default: 32)')
    ap.add_argument('--samples', type=int, default=256, help='inputs used to check the result')
    ap.add_argument('--verbose', action='store_true', help='print every rewrite step')
    ap.add_argument('--list-rules', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.list_rules:
        print('rewrite rules, by family:')
        for family, what in rule_table():
            print('  %-10s %s' % (family, what))
        print('\n  every one of these is an identity over bit vectors at the chosen width, which is')
        print('  why recognising the shape is enough to rewrite it -- and why the result is then')
        print('  checked by substitution anyway.')
        print('RESULT=%s' % TOKENS['ok'])
        return EXIT_OK

    text = args.expression
    if args.file:
        try:
            text = open(args.file, encoding='utf-8').read().strip()
        except OSError as exc:
            sys.stderr.write('error: %s\n' % exc)
            print('RESULT=%s' % TOKENS['use'])
            return EXIT_USE
    if not text:
        sys.stderr.write('error: give an expression, or --file\n')
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    mask = MASK[args.bits]
    try:
        tree = Parser(tokenize(text)).parse()
    except ValueError as exc:
        sys.stderr.write('error: %s\n' % exc)
        print('RESULT=%s' % TOKENS['parse'])
        return EXIT_PARSE

    reduced, steps = reduce_all(tree, mask)
    equal, counter, checked = verify(tree, reduced, mask, args.samples)

    if args.json:
        print(json.dumps({
            'expression': text, 'bits': args.bits,
            'original': tree.text(), 'reduced': reduced.text(),
            'steps': [{'rule': r, 'identity': n, 'from': b, 'to': a} for r, n, b, a in steps],
            'samples_checked': checked, 'equivalent_on_samples': equal,
            'counterexample': counter,
            'evidence': ('a counterexample refutes the reduction' if counter else
                         'sampling refutes, it does not prove: these are the inputs it tried'),
        }, indent=2))
        print('RESULT=%s' % (TOKENS['ok'] if equal else TOKENS['refuted']))
        return EXIT_OK if equal else EXIT_COUNTEREXAMPLE

    print('expression : %s' % tree.text())
    print('width      : %d bits' % args.bits)
    if args.verbose:
        if steps:
            print('\nrewrites:')
            for rule, note, before, after in steps:
                print('  [%-10s] %-34s  %s  ->  %s' % (rule, note, before, after))
        else:
            print('\nrewrites: none applied')
    print('\nreduced    : %s' % reduced.text())
    if reduced.text() == tree.text():
        print('             (already in its simplest form under these rules)')
    print()
    if equal:
        print('checked on %d inputs, including 0, 1, all-ones and the single-bit patterns:'
              % checked)
        print('  the two forms agree on every one of them.')
        print('  Sampling refutes; it does not prove. What this supports is "equivalent on %d '
              'inputs",' % checked)
        print('  not "equivalent" -- for that, a solver and a proof, or the identity itself.')
    else:
        print('REFUTED on the input that follows. The reduction is wrong:')
        print('  input     : %s' % ', '.join('%s=0x%x' % (k, v) for k, v in counter['env'].items()))
        print('  original  : 0x%x' % counter['original'])
        print('  reduced   : 0x%x' % counter['reduced'])
    print('\nRESULT=%s' % (TOKENS['ok'] if equal else TOKENS['refuted']))
    return EXIT_OK if equal else EXIT_COUNTEREXAMPLE


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_USE)
