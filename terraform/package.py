#!/usr/bin/env python3
"""Package the Find Evil Splunk apps into installable .spl archives.

Produces terraform/dist/<app>.spl (gzip-compressed tar, app folder at the root) for
each app, ready to be installed by the splunk_apps_local Terraform resource.

Run standalone (`python3 package.py`) or automatically via the null_resource in main.tf.
"""
import os
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DIST = os.path.join(HERE, "dist")
APPS = ["find_evil", "forensics_ingest"]
EXCLUDE = {"__pycache__", ".DS_Store", ".git"}
EXCLUDE_SUFFIX = (".pyc", ".pyo")


def _filter(info):
    base = os.path.basename(info.name)
    if base in EXCLUDE or any(info.name.endswith(s) for s in EXCLUDE_SUFFIX):
        return None
    if "/__pycache__/" in info.name:
        return None
    return info


def package(app):
    src = os.path.join(REPO, "splunk_app", app)
    if not os.path.isdir(src):
        raise SystemExit(f"app source not found: {src}")
    out = os.path.join(DIST, f"{app}.spl")
    with tarfile.open(out, "w:gz") as tar:
        # arcname=app puts the app folder at the archive root, as Splunk expects.
        tar.add(src, arcname=app, filter=_filter)
    size = os.path.getsize(out)
    print(f"  {app:18s} -> dist/{app}.spl ({size/1024:.0f} KB)")


def main():
    os.makedirs(DIST, exist_ok=True)
    print("[package] building .spl archives…")
    for app in APPS:
        package(app)
    print("OK — archives written to", DIST)


if __name__ == "__main__":
    main()
