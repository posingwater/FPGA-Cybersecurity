import argparse
import hashlib
import json
import sys
from pathlib import Path

from code import ml_kem_decaps, ml_kem_encaps, ml_kem_keygen


def _decode_hex(test: dict, field: str, case_name: str) -> bytes:
    value = test.get(field)
    if not isinstance(value, str):
        raise ValueError(f"{case_name}: expected a hex string in field {field!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{case_name}: invalid hex in field {field!r}") from error


def _check_output(case_name: str, field: str, actual: bytes, expected: bytes) -> bool:
    if actual == expected:
        print(f"  PASS {case_name}: {field}")
        return True

    actual_hash = hashlib.sha256(actual).hexdigest()
    expected_hash = hashlib.sha256(expected).hexdigest()
    print(
        f"  FAIL {case_name}: {field} mismatch "
        f"(expected sha256 {expected_hash}, got {actual_hash})"
    )
    return False


def _run_test(group: dict, test: dict, file_name: str) -> tuple[int, int]:
    case_name = f"{file_name} tgId={group.get('tgId', '?')} tcId={test.get('tcId', '?')}"
    parameter_set = group.get("parameterSet")
    if parameter_set is not None and parameter_set != "ML-KEM-768":
        raise ValueError(
            f"{case_name}: this implementation supports ML-KEM-768, "
            f"not {parameter_set!r}"
        )

    passed = 0
    total = 0

    if "d" in test or "z" in test:
        d = _decode_hex(test, "d", case_name)
        z = _decode_hex(test, "z", case_name)
        ek, dk = ml_kem_keygen(d=d, z=z)
        for field, actual in (("ek", ek), ("dk", dk)):
            expected = _decode_hex(test, field, case_name)
            total += 1
            passed += _check_output(case_name, field, actual, expected)

    if "ek" in test and "m" in test:
        ek = _decode_hex(test, "ek", case_name)
        message = _decode_hex(test, "m", case_name)
        shared_key, ciphertext = ml_kem_encaps(ek, m=message)
        for field, actual in (("c", ciphertext), ("k", shared_key)):
            expected = _decode_hex(test, field, case_name)
            total += 1
            passed += _check_output(case_name, field, actual, expected)

        if "dk" in test:
            decaps_key = _decode_hex(test, "dk", case_name)
            decaps_key_output = ml_kem_decaps(decaps_key, ciphertext)
            expected_key = _decode_hex(test, "k", case_name)
            total += 1
            passed += _check_output(case_name, "decaps k", decaps_key_output, expected_key)

    if total == 0:
        raise ValueError(
            f"{case_name}: unrecognized test; expected keyGen fields "
            "(d, z, ek, dk) or encapsulation fields (ek, m, c, k)"
        )
    return passed, total


def run_kat_files(file_paths: list[Path]) -> bool:
    total_passed = 0
    total_checks = 0

    for file_path in file_paths:
        try:
            with file_path.open(encoding="utf-8") as vector_file:
                vectors = json.load(vector_file)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"could not read {file_path}: {error}") from error

        groups = vectors.get("testGroups") if isinstance(vectors, dict) else None
        if not isinstance(groups, list):
            raise ValueError(f"{file_path}: expected a JSON object with a testGroups array")

        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("tests"), list):
                raise ValueError(f"{file_path}: each test group must contain a tests array")
            for test in group["tests"]:
                if not isinstance(test, dict):
                    raise ValueError(f"{file_path}: each test case must be a JSON object")
                passed, checks = _run_test(group, test, file_path.name)
                total_passed += passed
                total_checks += checks

    print(f"\nKAT result: {total_passed}/{total_checks} checks passed.")
    return total_passed == total_checks


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate NIST ACVP ML-KEM-768 JSON known-answer vectors."
    )
    parser.add_argument(
        "vectors",
        type=Path,
        nargs="+",
        help="one or more NIST JSON vector files (for example keyGen and encapDecap)",
    )
    args = parser.parse_args()

    try:
        return 0 if run_kat_files(args.vectors) else 1
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
