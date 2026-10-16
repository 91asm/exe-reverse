#!/usr/bin/env python3
"""Re-wrap prose paragraphs in a markdown file to a wider margin.

Content-preserving: joins each paragraph (or bullet item, or numbered item) into
one logical string and re-splits it at WIDTH. Headings, table rows, fenced code
blocks, blank lines and horizontal rules are passed through untouched.
"""
import re
import sys

WIDTH = 112
BULLET = re.compile(r'^(- |\d+\. )')
CONT = re.compile(r'^(\s+)')


def is_prose(line):
    s = line.strip()
    if not s:
        return False
    if s.startswith(('#', '|', '>', '```', '~~~', '---')):
        return False
    return True


def prefix_of(first):
    m = BULLET.match(first)
    if m:
        return m.group(1), ' ' * len(m.group(1))
    return '', ''


def wrap(words, prefix, hang):
    lines, cur, first = [], '', True
    for w in words:
        if first:
            cur = prefix + w
            first = False
        elif len(cur) + 1 + len(w) <= WIDTH:
            cur += ' ' + w
        else:
            lines.append(cur)
            cur = hang + w
    if cur.strip():
        lines.append(cur)
    return lines


def main(path):
    with open(path, encoding='utf-8') as fh:
        lines = fh.read().splitlines()

    out, block, in_fence = [], [], False
    for raw in lines:
        if raw.strip().startswith('```') or raw.strip().startswith('~~~'):
            if block:
                out.extend(flush(block))
                block = []
            in_fence = not in_fence
            out.append(raw)
            continue
        if in_fence:
            out.append(raw)
            continue
        if is_prose(raw):
            if block and not (raw.startswith((' ', '\t')) or BULLET.match(raw)):
                # a new paragraph started without a blank line
                out.extend(flush(block))
                block = []
            block.append(raw)
            continue
        if block:
            out.extend(flush(block))
            block = []
        out.append(raw)
    if block:
        out.extend(flush(block))

    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(out) + '\n')
    return len(lines), len(out)


def flush(block):
    prefix, hang = prefix_of(block[0])
    body = block[0][len(prefix):] if prefix else block[0]
    rest = [b.strip() for b in block[1:]]
    text = ' '.join([body.strip()] + rest)
    return wrap(text.split(), prefix, hang)


if __name__ == '__main__':
    before, after = main(sys.argv[1])
    print('%s: %d -> %d lines' % (sys.argv[1], before, after))
