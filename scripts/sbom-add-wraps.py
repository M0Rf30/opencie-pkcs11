#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Gianluca Boiano
# SPDX-License-Identifier: LGPL-3.0-or-later
"""Complete a Syft CycloneDX SBOM with the Meson wrap dependencies.

Syft has no Meson cataloger, so the third-party sources this project vendors
through ``subprojects/*.wrap`` are invisible to it. This script reads the pins
(name, version, URL, SHA-256) straight from the wrap files and merges them into
the Syft document, then names the described component after the release.

It also drops what Syft reports about the repository itself rather than about
the shipped binaries: GitHub Actions found in the workflow files (CI tooling)
and bare file entries (which carry build-machine paths).

Libraries resolved from the system or from vcpkg (OpenSSL, libcurl, FreeType,
libpng, OpenJPEG, zlib, ...) are not pinned in the repository and therefore
cannot be listed with a version; the SBOM records that in a property.

Usage: sbom-add-wraps.py SYFT_SBOM.json TAG OUTPUT.json [SUBPROJECTS_DIR]
"""

import configparser
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

REPO = "M0Rf30/opencie-pkcs11"

# Wraps that are only used to build the test suite; not part of any release
# artifact. Kept in the SBOM (they are pinned in the repository) but marked
# as excluded from the shipped product.
TEST_ONLY_WRAPS = {"catch2"}

SCOPE_NOTE = (
    "Meson wrap sources are pinned and listed. Libraries resolved from the "
    "build system's packages or from vcpkg (e.g. OpenSSL, libcurl, FreeType, "
    "libpng, OpenJPEG, zlib) and the C++ runtime are not pinned in the "
    "repository and are not listed with versions."
)


def wrap_component(path: Path) -> dict:
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")
    if not cp.has_section("wrap-file"):
        raise SystemExit(f"{path}: not a wrap-file")
    sec = cp["wrap-file"]

    filename = sec.get("source_filename", "")
    m = re.match(r"^(?P<name>.+?)-(?P<ver>\d[^-]*?)\.(?:tar\.\w+|tgz|zip)$", filename)
    if not m:
        raise SystemExit(f"{path}: cannot derive name/version from {filename!r}")
    name, version = m["name"], m["ver"]
    url = sec["source_url"]
    sha256 = sec["source_hash"].lower()

    purl = (
        f"pkg:generic/{quote(name)}@{quote(version)}"
        f"?download_url={quote(url, safe='')}&checksum=sha256:{sha256}"
    )
    comp = {
        "type": "library",
        "bom-ref": f"meson-wrap:{path.stem}@{version}",
        "name": name,
        "version": version,
        "scope": "excluded" if path.stem in TEST_ONLY_WRAPS else "required",
        "purl": purl,
        "hashes": [{"alg": "SHA-256", "content": sha256}],
        "externalReferences": [{"type": "distribution", "url": url}],
        "properties": [{"name": "meson:wrap", "value": f"subprojects/{path.name}"}],
    }
    fallback = sec.get("source_fallback_url")
    if fallback:
        comp["externalReferences"].append(
            {"type": "distribution", "url": fallback, "comment": "fallback"}
        )
    return comp


def main(argv: list[str]) -> int:
    if len(argv) not in (4, 5):
        print(__doc__, file=sys.stderr)
        return 2
    src, tag, dst = Path(argv[1]), argv[2], Path(argv[3])
    subprojects = Path(argv[4]) if len(argv) == 5 else Path("subprojects")

    bom = json.loads(src.read_text(encoding="utf-8"))
    if bom.get("bomFormat") != "CycloneDX":
        raise SystemExit(f"{src}: not a CycloneDX document")

    components = [
        c
        for c in bom.get("components", [])
        if c.get("type") != "file"
        and not str(c.get("purl", "")).startswith("pkg:github/")
    ]
    kept_refs = {c.get("bom-ref") for c in components}

    wraps = sorted(subprojects.glob("*.wrap"))
    if not wraps:
        raise SystemExit(f"no *.wrap files found in {subprojects}")
    wrap_comps = [wrap_component(p) for p in wraps]
    components.extend(wrap_comps)
    bom["components"] = components

    meta = bom.setdefault("metadata", {})
    root_ref = f"pkg:github/{REPO}@{tag}"
    meta["component"] = {
        "type": "library",
        "bom-ref": root_ref,
        "name": "libopencie-pkcs11",
        "version": tag,
        "purl": root_ref,
        "licenses": [{"license": {"id": "LGPL-3.0-or-later"}}],
        "externalReferences": [
            {"type": "vcs", "url": f"https://github.com/{REPO}"}
        ],
    }
    props = meta.setdefault("properties", [])
    props.append({"name": "opencie:sbom-scope", "value": SCOPE_NOTE})

    # Rebuild the dependency graph: the release depends on the wraps; drop
    # entries pointing at the components removed above.
    deps = [
        d
        for d in bom.get("dependencies", [])
        if d.get("ref") in kept_refs
    ]
    deps.append(
        {
            "ref": root_ref,
            "dependsOn": [c["bom-ref"] for c in wrap_comps if c["scope"] == "required"],
        }
    )
    deps.extend({"ref": c["bom-ref"]} for c in wrap_comps)
    bom["dependencies"] = deps

    dst.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print(f"{dst}: {len(components)} components ({len(wrap_comps)} from Meson wraps)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
