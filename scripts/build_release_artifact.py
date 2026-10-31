"""Build a manifest-exact release ZIP. Never installs, stages or changes HOME."""
from __future__ import annotations

import argparse
import hashlib
import io
import zipfile
from pathlib import Path

from artifact_identity import distribution_manifest, safe_file


def build(root: Path, output: Path) -> None:
    root = root.resolve(strict=True)
    if output.resolve().is_relative_to(root):
        raise RuntimeError("release ZIP must be outside the source tree")
    files = distribution_manifest(root)
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, expected in sorted(files.items()):
            if ".git" in Path(relative).parts or relative.endswith("/manage_plugin.py"):
                raise RuntimeError("removed installer or Git metadata in artifact")
            body = safe_file(root, relative).read_bytes()
            if hashlib.sha256(body).hexdigest() != expected:
                raise RuntimeError("artifact source changed during packaging")
            entry = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, body)
    # Complete validation precedes the exclusive output creation. No overwrite.
    with output.open("xb") as stream:
        stream.write(payload.getvalue())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.repo_root, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
