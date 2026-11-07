import argparse
import hashlib
import hmac
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
from run_tests import ESP_CLANG, ROOT, execute, windows_environment


KEYS = (b"0123456789ABCDEFGHIJKLMNOPQRSTUV", b"abcdefghijklmnopqrstuvwxyz012345")
POLICIES = {"disabled": (False, False), "mixed": (True, False), "required": (True, True)}


def good_ring(first_id=1):
    return [(first_id, KEYS[0] + b"\0"), (2, KEYS[1] + b"\0")]


def make_case(name, policy="mixed"):
    return dict(name=name, policy=POLICIES[policy], ring=good_ring(),
                vector_ring=good_ring(), active=1, ready=True, header=True)


def header_default_policy():
    # The un-overridden cases expect whatever policy ESP32PTPL2FollowerSettings.h ships with.
    text = (ROOT / "main" / "ESP32PTPL2FollowerSettings.h").read_text(encoding="utf-8")
    values = {}
    for name in ("FOLLOWER_PTP_AUTH_ENABLED", "FOLLOWER_PTP_AUTH_REQUIRED"):
        match = re.search(rf"^\s*#define\s+{name}\s+([01])\b", text, re.MULTILINE)
        if not match:
            raise RuntimeError(f"{name} default not found in ESP32PTPL2FollowerSettings.h")
        values[name] = match.group(1) == "1"
    return values["FOLLOWER_PTP_AUTH_ENABLED"], values["FOLLOWER_PTP_AUTH_REQUIRED"]


def cases():
    for policy in POLICIES:
        yield make_case(policy, policy)
    default_required = header_default_policy()[1]
    for empty in (False, True):
        case = make_case("header_default_empty" if empty else "header_default")
        case["policy"] = None
        if empty:
            case.update(ring=[], ready=not default_required)
        yield case
    case = make_case("required_disabled")
    case.update(policy=(False, True), ready=False)
    yield case
    for policy in ("mixed", "required"):
        for kind in ("empty", "too_many", "duplicate", "zero_id", "missing_active",
                     "short", "punctuation", "nonnul"):
            case = make_case(f"{policy}_{kind}", policy)
            ring = case["ring"]
            if kind == "empty":
                ring = []
            elif kind == "too_many":
                ring = [(index, KEYS[0] + b"\0") for index in range(1, 6)]
            elif kind == "duplicate":
                ring[1] = (1, ring[1][1])
            elif kind == "zero_id":
                ring[1] = (0, ring[1][1])
            elif kind == "missing_active":
                ring[0] = (3, ring[0][1])
            elif kind == "short":
                ring[0] = (1, b"short" + bytes(28))
            elif kind == "punctuation":
                ring[0] = (1, b"!" + KEYS[0][1:] + b"\0")
            else:
                ring[0] = (1, KEYS[0] + b"X")
            case.update(ring=ring, ready=kind == "empty" and policy == "mixed")
            yield case
    case = make_case("boundary_ids")
    case.update(ring=good_ring(0xFFFFFFFF), vector_ring=good_ring(0xFFFFFFFF), active=0xFFFFFFFF)
    yield case
    case = make_case("rotated_active_2")
    case["active"] = 2
    yield case
    case = make_case("disabled_empty", "disabled")
    case["ring"] = []
    yield case
    for policy in POLICIES:
        case = make_case(f"{policy}_no_header", policy)
        case.update(header=False, ready=policy != "required")
        yield case


def array_literal(packet):
    values = bytes(packet).ljust(128, b"\0")
    if len(values) != 128:
        raise ValueError("Invalid vector size")
    rows = ["    " + ", ".join(f"0x{value:02x}" for value in values[index:index + 16])
            for index in range(0, 128, 16)]
    return "{{\n" + ",\n".join(rows) + "\n}}"


def sign(packet, key_id, key):
    packet = bytearray(packet)
    packet[1] = 0x12
    packet[2:4] = (len(packet) + 26).to_bytes(2, "big")
    packet.extend(bytes((0x80, 0x09, 0, 0x16, 1, 0)))
    packet.extend(key_id.to_bytes(4, "big"))
    packet.extend(hmac.new(key[:32], packet, hashlib.sha256).digest()[:16])
    return packet


def server_frame(kind, sequence, signed, key):
    size = 64 if kind == 11 else 54 if kind == 9 else 44
    packet = bytearray(size)
    packet[0] = kind
    packet[1] = 2
    packet[2:4] = size.to_bytes(2, "big")
    packet[20:30] = bytes.fromhex("80f1b2fffed2ca9a0001")
    packet[30:32] = sequence.to_bytes(2, "big")
    packet[32] = 0 if signed else {11: 5, 0: 0, 8: 2, 9: 3}[kind]
    if kind == 11:
        packet[6:8] = (0x003C).to_bytes(2, "big")
        packet[44:46] = (37).to_bytes(2, "big")
        packet[47:50] = bytes((128, 6, 0x22))
        packet[50:52] = (100).to_bytes(2, "big")
        packet[52] = 128
        packet[53:61] = packet[20:28]
        packet[63] = 0x20
    else:
        if kind == 0:
            packet[6:8] = (0x0200).to_bytes(2, "big")
        if kind in (8, 9):
            packet[34:40] = (100).to_bytes(6, "big")
            packet[40:44] = (1000 if kind == 8 else 100003000).to_bytes(4, "big")
        if kind == 9:
            packet[44:54] = bytes.fromhex("82f1b2fffed2ca9a0001")
    if signed:
        packet = sign(packet, *key)
    return bytes.fromhex("011b1900000080f1b2d2ca9a88f7") + packet


def write_fixtures(directory, case):
    for name in ("auth.cpp", "auth.h", "ESP32PTPL2FollowerSettings.h", "setting_types.h", "follower_core.h"):
        shutil.copyfile(ROOT / "main" / name, directory / name)
    if case["header"]:
        entries = ["{" + str(key_id) + "u, {" + ", ".join(map(str, value)) + "}}"
                   for key_id, value in case["ring"]]
        (directory / "ESP32PTPL2FollowerSettingsSecrets.h").write_text(
            '#pragma once\nnamespace follower::settings {\n'
            f'inline constexpr std::array<PtpKey, {len(entries)}> ptp_symmetric_keys'
            '{{' + ",\n".join(entries) + '}};\n}\n', encoding="utf-8")
    enabled = (case["policy"] or header_default_policy())[0]
    packet = bytearray((index * 7 + 3) & 255 for index in range(44))
    packet[:4] = bytes((0, 0x12 if enabled else 0x02, 0, 44))
    lines = ['#pragma once', '#include <array>', '#include <cstdint>', 'namespace vectors {',
             'inline constexpr std::array<uint8_t, 128> ptp_unsigned' + array_literal(packet) + ';']
    ring = case["vector_ring"]
    active = next(entry for entry in ring if entry[0] == case["active"])
    other = next(entry for entry in ring if entry[0] != case["active"])
    for role, key in (("active", active), ("other", other)):
        lines.append(f'inline constexpr std::array<uint8_t, 128> ptp_signed_{role}' +
                     array_literal(sign(packet, *key)) + ';')
    for signed in (False, True):
        name = "signed_server" if signed else "unsigned_server"
        frames = [server_frame(kind, sequence, signed, active)
                  for kind, sequence in ((11, 1), (11, 2), (0, 17), (8, 17), (9, 9))]
        lines.append(f'inline constexpr std::array<std::array<uint8_t, 128>, 5> {name}' +
                     '{{\n' + ",\n".join(array_literal(frame) for frame in frames) + '\n}};')
    lines.append('}')
    (directory / "auth_vectors.h").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", choices=("auto", "esp-clang", "msvc"), default="auto")
    args = parser.parse_args()
    env = windows_environment(None)
    compiler = args.compiler
    if compiler == "auto":
        targets = subprocess.run([str(ESP_CLANG), "--print-targets"], capture_output=True,
                                 text=True, check=True).stdout if ESP_CLANG.is_file() else ""
        compiler = "esp-clang" if "x86-64" in targets else "msvc"
    executable_compiler = str(ESP_CLANG) if compiler == "esp-clang" else shutil.which("cl.exe", path=env.get("PATH"))
    if not executable_compiler:
        raise RuntimeError("VS2022 cl.exe was not found")
    count = processes = 0
    with tempfile.TemporaryDirectory(prefix="ESP32PTPL2Follower-auth-tests-") as temporary:
        for case in cases():
            directory = Path(temporary) / case["name"]
            directory.mkdir()
            write_fixtures(directory, case)
            enabled, required = case["policy"] or header_default_policy()
            expected_keys = len(case["ring"]) if case["ready"] and enabled and case["header"] else 0
            definitions = [f"EXPECT_PTP_READY={int(case['ready'])}", f"EXPECT_PTP_KEYS={expected_keys}",
                           f"EXPECT_PTP_ENABLED={int(enabled)}", f"EXPECT_PTP_REQUIRED={int(required)}",
                           f"FOLLOWER_PTP_ACTIVE_KEY_ID={case['active']}u", "FOLLOWER_PTP_AUTH_SPP=1"]
            if case["policy"] is not None:
                definitions += [f"FOLLOWER_PTP_AUTH_ENABLED={int(enabled)}",
                                f"FOLLOWER_PTP_AUTH_REQUIRED={int(required)}"]
            sources = [ROOT / "tests" / "auth_host" / "psa_crypto.cpp", ROOT / "tests" / "auth_tests.cpp",
                       directory / "auth.cpp", ROOT / "main" / "follower_core.cpp"]
            includes = [directory, ROOT / "tests" / "auth_host"]
            executable = directory / "auth_tests.exe"
            if compiler == "msvc":
                command = [executable_compiler, "/nologo", "/std:c++17", "/W4", "/WX", "/EHsc",
                           "/permissive-", "/D_CRT_SECURE_NO_WARNINGS",
                           *("/D" + value for value in definitions), *("/I" + str(path) for path in includes),
                           *sources, f"/Fe:{executable}", "/link", "bcrypt.lib"]
            else:
                command = [executable_compiler, "--target=x86_64-pc-windows-msvc", "-std=c++17",
                           "-Wall", "-Wextra", "-Werror", "-D_CRT_SECURE_NO_WARNINGS",
                           *("-D" + value for value in definitions),
                           *(flag for path in includes for flag in ("-I", path)),
                           *sources, "-Xlinker", "bcrypt.lib", "-o", executable]
            print(f"BUILD {case['name']} ({compiler}); synthetic public keys only", flush=True)
            if execute(command, env, directory):
                return 1
            count += 1
            if execute([executable], env, directory):
                return 1
            processes += 1
            if case["name"] in ("mixed", "required"):
                for failure in ("init", "import", "import_second"):
                    if execute([executable, failure, 0, 0], env, directory):
                        return 1
                    processes += 1
            elif enabled and not required and (not case["header"] or not case["ring"]):
                for failure in ("init", "import"):
                    if execute([executable, failure, 1, 0], env, directory):
                        return 1
                    processes += 1
    print(f"PASS: {count} cases, {processes} test processes; real PTP auth/parser/selection/matching/math, host PSA backend; no hardware claims", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
