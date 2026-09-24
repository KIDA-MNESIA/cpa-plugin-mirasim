"""Validate release assets and prepare a CLIProxyAPI Plugins Store submission."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile


PLUGIN_ID = "mirasim"
PLATFORMS = {
    "linux_amd64": "so",
    "linux_arm64": "so",
    "darwin_amd64": "dylib",
    "darwin_arm64": "dylib",
    "windows_amd64": "dll",
    "windows_arm64": "dll",
    "freebsd_amd64": "so",
}


def release_version(tag):
    if not re.fullmatch(r"v[0-9]+(?:\.[0-9]+)+", tag):
        raise ValueError("store releases require a dotted numeric tag, for example v0.7.1")
    return tag[1:]


def verify_release(directory, tag):
    version = release_version(tag)
    expected = {
        f"{PLUGIN_ID}_{version}_{platform}.zip": f"{PLUGIN_ID}.{extension}"
        for platform, extension in PLATFORMS.items()
    }
    actual = {path.name for path in directory.glob("*.zip")}
    if actual != expected.keys():
        raise ValueError(
            f"release archives mismatch: missing={sorted(expected.keys() - actual)}, "
            f"unexpected={sorted(actual - expected.keys())}"
        )
    sidecars = {path.name for path in directory.glob("*.sha256")}
    if sidecars != {name + ".sha256" for name in expected}:
        raise ValueError("release must contain exactly one SHA-256 sidecar per archive")
    checksums = []
    for name, library in sorted(expected.items()):
        archive = directory / name
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        line = f"{digest}  {name}"
        if (directory / (name + ".sha256")).read_text(encoding="utf-8").strip() != line:
            raise ValueError(f"checksum mismatch: {name}")
        with zipfile.ZipFile(archive) as zipped:
            entries = zipped.infolist()
            if len(entries) != 1 or entries[0].filename != library:
                raise ValueError(f"{name} must contain only {library} at the ZIP root")
            entry = entries[0]
            mode = entry.external_attr >> 16
            if entry.is_dir() or (stat.S_IFMT(mode) and not stat.S_ISREG(mode)):
                raise ValueError(f"{name}: library must be a regular file")
            if entry.file_size == 0 or zipped.testzip() is not None:
                raise ValueError(f"{name}: empty or corrupt library")
        checksums.append(line)
    (directory / "checksums.txt").write_text(
        "\n".join(checksums) + "\n", encoding="utf-8", newline="\n"
    )
    return sorted(expected)


def store_entry(repository, author):
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("repository must be https://github.com/{owner}/{repo}")
    if repository.endswith(".git"):
        raise ValueError("repository must not end with .git")
    if not author.strip():
        raise ValueError("author must not be empty")
    return {
        "id": PLUGIN_ID,
        "name": "Mirasim Provider",
        "description": (
            "Adds Mirasim OAuth accounts, text and image routing, "
            "dynamic models, token refresh, and quota reporting to CLIProxyAPI."
        ),
        "author": author.strip(),
        "repository": repository,
        "homepage": repository,
        "license": "MIT",
        "tags": ["Provider", "Mirasim", "Claude", "Codex"],
    }


def prepare_submission(directory, repository, author, tag):
    version = release_version(tag)
    entry = store_entry(repository, author)
    registry = {"schema_version": 1, "plugins": [entry]}
    assets = [f"{PLUGIN_ID}_{version}_{platform}.zip" for platform in sorted(PLATFORMS)]
    assets.append("checksums.txt")
    links = "\n".join(
        f"- [{name}]({repository}/releases/download/{tag}/{name})" for name in assets
    )
    body = (
        "# Add Mirasim Provider\n\n"
        f"{entry['description']}\n\n"
        f"Plugin repository: {repository}\n\n"
        f"Release: [{tag}]({repository}/releases/tag/{tag})\n\n"
        f"Release assets:\n\n{links}\n\n"
        "The registry entry omits the legacy version field so CLIProxyAPI resolves "
        "updates from the latest GitHub Release.\n\n"
        "## Before submitting this draft\n\n"
        "- Verify this is the repository's latest published, non-draft, non-prerelease release.\n"
        "- Verify every asset link above and checksums.txt after publication.\n"
        "- Test installation, loading, OAuth, and an actual client request through a custom store source.\n"
        "- Add only the plugins[0] entry to the official registry.json; preserve existing entries.\n"
        "- Replace this checklist with the actual validation results before opening the PR.\n"
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "registry.json").write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    (directory / "store-pr.md").write_text(body, encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    tag = commands.add_parser("validate-tag")
    tag.add_argument("--tag", required=True)
    verify = commands.add_parser("verify-release")
    verify.add_argument("--tag", required=True)
    verify.add_argument("--directory", type=Path, required=True)
    prepare = commands.add_parser("prepare-submission")
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--author", required=True)
    prepare.add_argument("--output-dir", type=Path, default=Path("dist/store"))
    args = parser.parse_args()
    try:
        if args.command == "validate-tag":
            print(release_version(args.tag))
        elif args.command == "verify-release":
            assets = verify_release(args.directory, args.tag)
            print(f"Verified {len(assets)} plugin archives; wrote checksums.txt")
        else:
            prepare_submission(args.output_dir, args.repository, args.author, args.tag)
            print(f"Wrote registry.json and store-pr.md to {args.output_dir}")
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
