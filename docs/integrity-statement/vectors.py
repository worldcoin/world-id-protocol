#!/usr/bin/env python3
"""Synthetic encoding reference for the draft, not a production protocol API."""

import copy
import hashlib
import json
from pathlib import Path
import sys

DOMAIN = b"worldcoin/proof-integrity/statement/v3"
MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIXTURES = Path(__file__).with_name("vectors.json")


def uint(value, width):
    if isinstance(value, str):
        value = int(value, 10)
    if type(value) is not int or not 0 <= value < 1 << (8 * width):
        raise ValueError("unsigned integer out of range")
    return value.to_bytes(width, "big")


def field(value):
    encoded = uint(value, 32)
    if int.from_bytes(encoded, "big") >= MODULUS:
        raise ValueError("noncanonical field")
    return encoded


def encode(statement):
    result = DOMAIN + uint(statement["rp_id"], 8) + field(statement["nonce"])
    result += uint(len(statement["items"]), 4)
    seen = set()
    for item in statement["items"]:
        identifier = item["identifier"]
        if identifier in seen:
            raise ValueError("duplicate identifier")
        seen.add(identifier)
        name = identifier.encode("utf-8")
        result += uint(len(name), 4) + name + uint(item["issuer_schema_id"], 8)
        binding = item["binding"]
        if binding["kind"] == "uniqueness":
            if set(binding) != {"kind", "nullifier"}:
                raise ValueError("invalid uniqueness binding")
            result += b"\x00" + field(binding["nullifier"])
        elif binding["kind"] == "session":
            if set(binding) != {"kind", "nullifier", "action"}:
                raise ValueError("invalid session binding")
            action = field(binding["action"])
            if action[0] != 2:
                raise ValueError("invalid session action prefix")
            result += b"\x01" + field(binding["nullifier"]) + action
        else:
            raise ValueError("unknown binding tag")
        result += uint(len(item["claims"]), 4)
        for claim in item["claims"]:
            result += field(claim)
    return result


def digest(statement):
    return hashlib.sha256(encode(statement)).hexdigest()


def sample_statements():
    face = {"identifier": "face", "issuer_schema_id": "11",
            "binding": {"kind": "uniqueness", "nullifier": "3"}, "claims": ["10"]}
    uniqueness = {"rp_id": "1", "nonce": "2", "items": [face]}
    session = copy.deepcopy(uniqueness)
    session["items"][0]["binding"] = {
        "kind": "session", "nullifier": "3", "action": str((2 << 248) + 4)}
    mixed = copy.deepcopy(session)
    mixed["items"].append({"identifier": "orb", "issuer_schema_id": "1",
                           "binding": {"kind": "uniqueness", "nullifier": "5"},
                           "claims": []})
    return {"uniqueness_face": uniqueness, "session_face": session, "mixed_items": mixed}


def validate():
    vectors = json.loads(FIXTURES.read_text())
    for vector in vectors:
        assert encode(vector["statement"]).hex() == vector["preimage_hex"], vector["name"]
        assert digest(vector["statement"]) == vector["sha256"], vector["name"]

    base = sample_statements()["mixed_items"]
    mutations = []
    for key in ["rp_id", "nonce"]:
        changed = copy.deepcopy(base)
        changed[key] = "9"
        mutations.append(changed)
    for key, value in [("identifier", "face2"), ("issuer_schema_id", "12"), ("claims", ["11"])]:
        changed = copy.deepcopy(base)
        changed["items"][0][key] = value
        mutations.append(changed)
    for key in ["nullifier", "action"]:
        changed = copy.deepcopy(base)
        changed["items"][0]["binding"][key] = str(int(changed["items"][0]["binding"][key]) + 1)
        mutations.append(changed)
    changed = copy.deepcopy(base)
    changed["items"][0]["binding"] = {"kind": "uniqueness", "nullifier": "3"}
    mutations.append(changed)
    changed = copy.deepcopy(base)
    changed["items"].reverse()
    mutations.append(changed)
    assert all(digest(changed) != digest(base) for changed in mutations)

    invalid = []
    for value in [-1, MODULUS, 1 << 256]:
        changed = copy.deepcopy(base)
        changed["nonce"] = str(value)
        invalid.append(changed)
    for binding in [{"kind": "other", "nullifier": "3"},
                    {"kind": "session", "nullifier": "3", "action": "4"},
                    {"kind": "uniqueness", "nullifier": "3", "action": "4"}]:
        changed = copy.deepcopy(base)
        changed["items"][0]["binding"] = binding
        invalid.append(changed)
    changed = copy.deepcopy(base)
    changed["items"].append(copy.deepcopy(changed["items"][0]))
    invalid.append(changed)
    for changed in invalid:
        try:
            encode(changed)
        except ValueError:
            continue
        raise AssertionError("invalid statement accepted")
    print(f"Verified {len(vectors)} vectors, {len(mutations)} mutations, {len(invalid)} rejections")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        FIXTURES.write_text(json.dumps([
            {"name": name, "statement": statement, "preimage_hex": encode(statement).hex(),
             "sha256": digest(statement)}
            for name, statement in sample_statements().items()
        ], indent=2) + "\n")
    elif sys.argv[1:]:
        raise SystemExit("usage: vectors.py [--write]")
    validate()
