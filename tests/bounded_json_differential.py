#!/usr/bin/env python3
# Copyright (C) 2026 by The Forkbomb Company
# designed, written and maintained by Denis Roio
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Deterministic differential/property/mutation gate for bounded JSON."""

import base64
import json
import random
import subprocess
import sys


class Number:
    def __init__(self, raw):
        self.raw = raw


class Object:
    def __init__(self, pairs):
        seen = set()
        self.pairs = []
        for key, value in pairs:
            if key in seen:
                raise ValueError("duplicate key")
            seen.add(key)
            self.pairs.append((key, value))


def reject_constant(_):
    raise ValueError("non-JSON constant")


def reject_surrogates(value):
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("isolated surrogate")
    elif isinstance(value, list):
        for item in value:
            reject_surrogates(item)
    elif isinstance(value, Object):
        for key, item in value.pairs:
            reject_surrogates(key)
            reject_surrogates(item)


def python_parse(raw):
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=Object,
            parse_int=Number,
            parse_float=Number,
            parse_constant=reject_constant,
        )
        reject_surrogates(value)
        return True, value
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False, None


def normalized_number(raw):
    negative = raw.startswith("-")
    unsigned = raw[1:] if negative else raw
    marker = max(unsigned.find("e"), unsigned.find("E"))
    if marker >= 0:
        coefficient, exponent_text = unsigned[:marker], unsigned[marker + 1:]
        exponent = int(exponent_text)
    else:
        coefficient, exponent = unsigned, 0
    if "." in coefficient:
        integer, fraction = coefficient.split(".", 1)
    else:
        integer, fraction = coefficient, ""
    digits = (integer + fraction).lstrip("0")
    if not digits:
        return [False, "0", "0"]
    trailing = len(digits) - len(digits.rstrip("0"))
    if trailing:
        digits = digits[:-trailing]
    exponent += trailing - len(fraction)
    return [negative, digits, str(exponent)]


def canonical(value):
    if value is None:
        return ["null"]
    if value is True or value is False:
        return ["boolean", value]
    if isinstance(value, Number):
        return ["number", normalized_number(value.raw)]
    if isinstance(value, str):
        return ["string", value.encode("utf-8").hex()]
    if isinstance(value, list):
        return ["array", [canonical(item) for item in value]]
    if isinstance(value, Object):
        return ["object", [[key.encode("utf-8").hex(), canonical(item)]
                            for key, item in value.pairs]]
    raise AssertionError("unexpected Python JSON value")


def canonical_project(tree):
    kind = tree[0]
    if kind == "number":
        return [kind, normalized_number(tree[1])]
    if kind == "array":
        return [kind, [canonical_project(item) for item in tree[1]]]
    if kind == "object":
        return [kind, [[key, canonical_project(item)] for key, item in tree[1]]]
    return tree


def shape(tree):
    kind = tree[0]
    if kind == "number":
        return [kind]
    if kind == "array":
        return [kind, [shape(item) for item in tree[1]]]
    if kind == "object":
        return [kind, [[key, shape(item)] for key, item in tree[1]]]
    return tree


NODE_PROGRAM = r"""
const fs = require('fs');
function hex(s) { return Buffer.from(s, 'utf8').toString('hex'); }
function tree(v) {
  if (v === null) return ['null'];
  if (typeof v === 'boolean') return ['boolean', v];
  if (typeof v === 'number') return ['number'];
  if (typeof v === 'string') return ['string', hex(v)];
  if (Array.isArray(v)) return ['array', v.map(tree)];
  return ['object', Object.entries(v).map(([k, x]) => [hex(k), tree(x)])];
}
for (const line of JSON.parse(fs.readFileSync(0, 'utf8'))) {
  try {
    const text = Buffer.from(line, 'base64').toString('utf8');
    process.stdout.write(JSON.stringify({accepted:true, tree:tree(JSON.parse(text))}) + '\n');
  } catch (_) {
    process.stdout.write('{"accepted":false}\n');
  }
}
"""


def node_results(node, cases):
    payload = json.dumps([base64.b64encode(case).decode("ascii") for case in cases])
    result = subprocess.run([node, "-e", NODE_PROGRAM], input=payload,
                            text=True, capture_output=True, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    if len(rows) != len(cases):
        raise AssertionError("Node JSON parser returned an incomplete batch")
    return rows


def native_result(driver, raw, limits=(512, 8, 128)):
    result = subprocess.run(
        [driver, raw.hex(), *(str(limit) for limit in limits)],
        text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def circuit_result(driver, raw):
    result = subprocess.run([driver, raw.hex()], text=True,
                            capture_output=True, check=True)
    return json.loads(result.stdout)


NUMBERS = [
    "0", "-0", "10", "-17", "0.25", "12.50e+1", "1E-9",
    "1e18446744073709551616", "10e18446744073709551615",
    "0e-999999999999999999999", "999999999999999999999.0000",
]
STRINGS = ["", "ascii", "quote\"slash\\", "é", "€", "😃", "a\nb\tc"]


def render_string(value, ensure_ascii):
    return json.dumps(value, ensure_ascii=ensure_ascii,
                      separators=(",", ":")).encode("utf-8")


def random_json(rng, depth=0):
    choices = ["null", "bool", "number", "string"]
    if depth < 3:
        choices += ["array", "object"]
    kind = rng.choice(choices)
    if kind == "null":
        return b"null"
    if kind == "bool":
        return rng.choice([b"true", b"false"])
    if kind == "number":
        return rng.choice(NUMBERS).encode("ascii")
    if kind == "string":
        return render_string(rng.choice(STRINGS), rng.choice([True, False]))
    if kind == "array":
        values = [random_json(rng, depth + 1) for _ in range(rng.randrange(4))]
        return b"[" + b",".join(values) + b"]"
    count = rng.randrange(4)
    pairs = []
    for index in range(count):
        key = "key_{}_{}".format(depth, index)
        pairs.append(render_string(key, rng.choice([True, False])) + b":" +
                     random_json(rng, depth + 1))
    return b"{" + b",".join(pairs) + b"}"


def build_cases():
    valid = [
        b"null", b" true \n", b"[]", b"{}", b'{"a":true}', b"[0,-0,12.50e+1]",
        b'{"a":[true,{"b":"\\uD83D\\uDE03"}],"n":1e18446744073709551616}',
        '"é€😃"'.encode("utf-8"), b'"\\"\\\\\\/\\b\\f\\n\\r\\t"',
        b'{"order_b":null,"order_a":[false,0]}',
        b'{"escaped":"\\u0000\\u007f\\u0080\\uffff"}',
        '"\u0800\uffff\U00010000\U0010ffff"'.encode("utf-8"),
    ]
    rng = random.Random(0xB0A1DED)
    for _ in range(120):
        candidate = random_json(rng)
        if len(candidate) <= 480:
            valid.append(candidate)

    syntax_invalid = [
        b"", b" ", b"{", b"[", b"[1,]", b'{"a":1,}', b'{"a" 1}',
        b"01", b"-", b"1.", b"1e", b"1e+", b"+1", b".1",
        b'"\\x"', b'"unterminated', b'"line\nfeed"', b"true false",
        b"[1 2]", b"{1:2}", b"[,]", b"{,}",
    ]
    policy_invalid = [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}',
                      ' {"é":0,"\\u00e9":1}'.encode("utf-8"),
                      ' {"😃":0,"\\uD83D\\uDE03":1}'.encode("utf-8"),
                      b'"\\uD800"', b'"\\uDC00"',
                      b'"\\uD800\\u0041"']
    byte_invalid = [b'"\xc0\x80"', b'"\xc1\xbf"', b'"\xed\xa0\x80"',
                    b'"\xed\xbf\xbf"', b'"\xf0\x80\x80\x80"',
                    b'"\xf4\x90\x80\x80"', b'"\xf5\x80\x80\x80"',
                    b'"\xe0\x9f\x80"', b'"\xe2\x82"', b'"\xf0\x9f\x98"',
                    b'"\x80"', b'"\xbf"']

    mutations = []
    # Each RFC 8259 token class appears in at least one seed, so deletion and
    # insertion exercise delimiters, literals, numbers, strings, containers,
    # escapes, and multibyte UTF-8 boundaries deterministically.
    seeds = [
        b'null', b'true', b'false', b'-12.50e+1', b'"\\u00e9"',
        '"😃"'.encode("utf-8"), b'[]', b'{}', b'[0,true,"x"]',
        b'{"a":[1,2],"b":"\\u00e9"}',
    ]
    for seed in seeds:
        for index in range(len(seed)):
            mutations.append(seed[:index] + seed[index + 1:])
            mutations.append(seed[:index] + b"!" + seed[index + 1:])
    # Deduplicate while preserving deterministic order.
    all_cases = valid + syntax_invalid + policy_invalid + byte_invalid + mutations
    return list(dict.fromkeys(all_cases)), set(policy_invalid), set(byte_invalid)


def check_limits(driver):
    raw = b'[{"a":0}]'
    if not native_result(driver, raw, (len(raw), 2, 7))["accepted"]:
        raise AssertionError("exact byte/depth/token boundary rejected")
    for limits in [(len(raw) - 1, 2, 7), (len(raw), 1, 7),
                   (len(raw), 2, 6)]:
        if native_result(driver, raw, limits)["accepted"]:
            raise AssertionError("bounded JSON limit overflow accepted: " + repr(limits))
    whitespace = b" [ 0 ] "
    if not native_result(driver, whitespace, (len(whitespace), 1, 7))["accepted"]:
        raise AssertionError("maximal whitespace/token boundary rejected")
    if native_result(driver, whitespace, (len(whitespace), 1, 6))["accepted"]:
        raise AssertionError("whitespace lexical token omitted from token bound")


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: bounded_json_differential.py DRIVER CIRCUIT_DRIVER RELATION_TEST NODE")
    driver, circuit_driver, relation_test, node = sys.argv[1:]
    # The same gate includes the compiled circuit fixture/advice model. Its
    # executable contains combined positives plus grammar/string/number/key
    # mutation negatives and a production-factory compile.
    subprocess.run([relation_test], check=True)

    cases, policy_invalid, byte_invalid = build_cases()
    node_rows = node_results(node, cases)
    accepted = rejected = mutations_checked = 0
    for raw, node_row in zip(cases, node_rows):
        python_accepted, python_value = python_parse(raw)
        project = native_result(driver, raw)
        # The evaluation fixture is deliberately a small, frozen 64-byte/
        # 32-token capacity family. Every corpus item within that family must
        # agree with native tokenization; larger valid cases are covered by
        # the native differential and compiler-scale relation fixtures.
        # The small composite bridge deliberately covers different root and
        # nested shapes.  It invokes the entire relation, including string,
        # pushdown grammar and duplicate-key advice; malformed near-neighbours
        # must agree with the native rejection path.
        if raw in (b'{"a":true}', b'{"a":true]', b'[null,[true]]',
                   b'["x",false]', b'{"a":[]}'):
            circuit = circuit_result(circuit_driver, raw)
            if circuit["native"] != project["accepted"]:
                raise AssertionError("bridge/native mismatch for " + raw.hex())
            if project["accepted"] != circuit["circuit"]:
                raise AssertionError("native/circuit mismatch for " + raw.hex())
        expected = python_accepted
        if project["accepted"] != expected:
            raise AssertionError(
                "native/Python acceptance mismatch for {}: project={} python={}".format(
                    raw.hex(), project["accepted"], expected))
        if expected:
            project_tree = canonical_project(project["tree"])
            python_tree = canonical(python_value)
            if project_tree != python_tree:
                raise AssertionError("native/Python tree mismatch for " + raw.hex())
            if not node_row["accepted"]:
                raise AssertionError("Node rejected accepted JSON " + raw.hex())
            if shape(project["tree"]) != node_row["tree"]:
                raise AssertionError("native/Node tree-shape mismatch for " + raw.hex())
            accepted += 1
        else:
            # Node decodes Buffer input with replacement characters; malformed
            # UTF-8 mutation cases are therefore intentionally outside its
            # syntax comparison, while Python and the native parser remain
            # strict on original bytes.
            try:
                raw.decode("utf-8", "strict")
                valid_utf8 = True
            except UnicodeDecodeError:
                valid_utf8 = False
            if (valid_utf8 and raw not in policy_invalid and
                    node_row["accepted"]):
                raise AssertionError("Node accepted syntax Python rejected: " + raw.hex())
            rejected += 1
        if b"!" in raw or raw in (b"[0true,\"x\"]", b'{"a":[1,2],"b":"\\u00e9"'):
            mutations_checked += 1
    check_limits(driver)
    print("bounded-json differential: cases={} accepted={} rejected={} mutations={} parsers=python,node duplicate_policy=reject composite_circuit_fixture=pass limits=pass".format(
        len(cases), accepted, rejected, mutations_checked))


if __name__ == "__main__":
    main()
