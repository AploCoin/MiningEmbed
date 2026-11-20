#!/usr/bin/env python3
"""Build portable behavior with actual AploEmbed crypto under ASan/UBSan."""

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SANITIZERS = ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
TEST_ENV = {
    **os.environ,
    "ASAN_OPTIONS": "halt_on_error=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}


def test_work(base, build):
    for name in ["sha3", "memzero"]:
        subprocess.run(
            [
                "cc",
                *SANITIZERS,
                "-I" + str(base / "src/trezor"),
                "-c",
                str(base / f"src/trezor/{name}.c"),
                "-o",
                str(build / f"{name}.o"),
            ],
            check=True,
        )
    binary = build / "work_test"
    subprocess.run(
        [
            "c++",
            "-std=c++11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *SANITIZERS,
            "-I" + str(ROOT / "src"),
            "-I" + str(base / "src/trezor"),
            str(ROOT / "tests/work_test.cpp"),
            str(ROOT / "src/MiningWork.cpp"),
            str(build / "sha3.o"),
            str(build / "memzero.o"),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True, env=TEST_ENV)


def test_progress(base, build, shared_objects):
    objects = list(shared_objects)
    for index, source in enumerate([
        ROOT / "src/provisioning/DeviceConfig.cpp",
        ROOT / "src/provisioning/SerialConfig.cpp",
        ROOT / "tests/serial_progress_test.cpp",
    ]):
        output = build / f"progress_{index}.o"
        subprocess.run([
            "c++", "-std=c++11", *SANITIZERS, "-O1", "-Wall", "-Wextra", "-Werror",
            "-ffunction-sections", "-fdata-sections",
            "-I" + str(ROOT / "tests/provisioning_stubs"),
            "-I" + str(ROOT / "src"), "-I" + str(base / "src"),
            "-c", str(source), "-o", str(output),
        ], check=True)
        objects.append(str(output))
    binary = build / "serial_progress_test"
    strip_flag = "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections"
    subprocess.run(["c++", *SANITIZERS, *objects, strip_flag, "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env=TEST_ENV)


def test_facade(base, build):
    flags = [
        *SANITIZERS,
        "-O1",
        "-DUSE_PRECOMPUTED_CP=0",
        "-ffunction-sections",
        "-fdata-sections",
        "-I" + str(ROOT / "tests"),
        "-I" + str(ROOT / "src"),
        "-I" + str(base / "src"),
        "-I" + str(base / "src/trezor"),
    ]
    objects = []
    for name in [
        "bignum",
        "ecdsa",
        "secp256k1",
        "sha3",
        "sha2",
        "hmac",
        "rfc6979",
        "memzero",
    ]:
        output = build / f"native_{name}.o"
        subprocess.run(
            ["cc", *flags, "-c", str(base / f"src/trezor/{name}.c"), "-o", str(output)],
            check=True,
        )
        objects.append(str(output))

    # The Web3 adapter is the board boundary; this fixture injects RPC instead.
    base_sources = sorted(
        path
        for path in (base / "src" / "session").glob("Session*.cpp")
        if path.name not in ("SessionKeysWeb3.cpp", "SessionSerial.cpp")
    )
    base_sources += sorted((base / "src/internal").glob("*.cpp"))
    sources = [
        *base_sources,
        base / "src/uint256/uint128_t.cpp",
        base / "src/uint256/uint256_t.cpp",
        ROOT / "src/MiningWork.cpp",
        ROOT / "src/MiningAbi.cpp",
        ROOT / "src/MiningEmbed.cpp",
        ROOT / "tests/host_platform.cpp",
        ROOT / "tests/facade_test.cpp",
    ]
    for index, source in enumerate(sources):
        output = build / f"facade_{index}.o"
        warnings = (
            ["-Wall", "-Wextra", "-Werror"]
            if source.parent in [ROOT / "src", ROOT / "tests"]
            else []
        )
        subprocess.run(
            [
                "c++",
                "-std=c++11",
                *flags,
                *warnings,
                "-c",
                str(source),
                "-o",
                str(output),
            ],
            check=True,
        )
        objects.append(str(output))

    binary = build / "facade_test"
    strip_flag = "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections"
    subprocess.run(
        ["c++", *SANITIZERS, *objects, strip_flag, "-o", str(binary)], check=True
    )
    subprocess.run([str(binary)], check=True, env=TEST_ENV)

    return objects[:-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--aploembed",
        type=Path,
        default=Path(os.environ.get("APLOEMBED_PATH", ROOT.parent / "AploEmbed")),
        help="supported AploEmbed checkout (default: sibling or APLOEMBED_PATH)",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=ROOT / "tests/.build",
        help="directory for isolated host objects and test binaries",
    )
    arguments = parser.parse_args()
    base = arguments.aploembed.resolve()
    if not (base / "src/SessionKeys.h").is_file():
        parser.error(
            "AploEmbed must include SessionKeys; pass --aploembed /path/to/AploEmbed"
        )
    build = arguments.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    test_work(base, build)
    shared_objects = test_facade(base, build)
    test_progress(base, build, shared_objects)


if __name__ == "__main__":
    main()
