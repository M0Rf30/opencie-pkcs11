#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""Assert that every symbol the version script exports is really exported.

Usage: check_exports.py <libopencie-pkcs11.so> <libopencie-pkcs11.map> [nm]

linker/libopencie-pkcs11.map is the public ABI. A name listed under
`global:` that the linker cannot resolve to a definition is silently dropped
(GNU ld does not warn), so a symbol can be declared in the headers, listed in
the map and still be missing from the shipped .so -- e.g. when its object
comes from a static archive and -Wl,--exclude-libs,ALL demotes it.

Android-only entry points (JNI bridge) are only built for Android and are
therefore not required on other hosts.
"""

import re
import subprocess
import sys

ANDROID_ONLY = re.compile(
    r"^(JNI_OnLoad|Java_.*|cie_set_nfc_tag|cie_clear_nfc_tag|cie_set_data_dir)$"
)


def map_globals(path):
    text = open(path, encoding="utf-8").read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    m = re.search(r"global:(.*?)(?:local:|\})", text, flags=re.S)
    if not m:
        sys.exit(f"{path}: no 'global:' section found")
    return set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*;", m.group(1)))


def exported(lib, nm):
    out = subprocess.run(
        [nm, "-D", "--defined-only", lib],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    # "<addr> <type> <name>[@@VERSION]"
    return {line.split()[-1].split("@")[0] for line in out.splitlines() if line.split()}


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    lib, mapfile = sys.argv[1], sys.argv[2]
    nm = sys.argv[3] if len(sys.argv) == 4 else "nm"

    wanted = {s for s in map_globals(mapfile) if not ANDROID_ONLY.match(s)}
    have = exported(lib, nm)
    missing = sorted(wanted - have)
    if missing:
        print(f"{lib}: {len(missing)} symbol(s) listed in {mapfile} are not exported:")
        for s in missing:
            print(f"  {s}")
        return 1
    print(f"all {len(wanted)} symbols from {mapfile} are exported by {lib}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
