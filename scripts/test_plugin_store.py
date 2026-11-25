import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from plugin_store import PLATFORMS, prepare_submission, release_version, verify_release


class PluginStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for platform, extension in PLATFORMS.items():
            self.write_archive(platform, [(f"mirasim.{extension}", b"library fixture")])

    def write_archive(self, platform, entries):
        archive = self.root / f"mirasim_0.7.1_{platform}.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for name, content in entries:
                zipped.writestr(name, content)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(".zip.sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n"
        )
        return archive

    def test_numeric_tags_only(self):
        for tag in ("v0.7.1", "v1.0", "v1.2.3.4"):
            self.assertEqual(release_version(tag), tag[1:])
        for tag in ("0.7.1", "v1", "v0.7.1-rc1", "v0.7.1+build", "v1..2", "v１.２", "v1.2\n"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_version(tag)

    def test_complete_release_writes_portable_checksums(self):
        names = verify_release(self.root, "v0.7.1")
        self.assertEqual(len(names), 7)
        checksums = (self.root / "checksums.txt").read_bytes()
        self.assertNotIn(b"\r", checksums)
        self.assertEqual(len(checksums.splitlines()), 7)
        for line in checksums.decode().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((self.root / name).read_bytes()).hexdigest())

    def test_missing_platform(self):
        (self.root / "mirasim_0.7.1_windows_arm64.zip").unlink()
        with self.assertRaisesRegex(ValueError, "missing="):
            verify_release(self.root, "v0.7.1")

    def test_unexpected_archive(self):
        (self.root / "mirasim_0.7.0_linux_amd64.zip").write_bytes(b"old release")
        with self.assertRaisesRegex(ValueError, "unexpected="):
            verify_release(self.root, "v0.7.1")

    def test_missing_checksum(self):
        (self.root / "mirasim_0.7.1_linux_amd64.zip.sha256").unlink()
        with self.assertRaisesRegex(ValueError, "sidecar"):
            verify_release(self.root, "v0.7.1")

    def test_checksum_mismatch_blocks_publication(self):
        (self.root / "mirasim_0.7.1_linux_amd64.zip").write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            verify_release(self.root, "v0.7.1")
        self.assertFalse((self.root / "checksums.txt").exists())

    def test_rejects_unsafe_or_incorrect_layouts(self):
        for name in ("dist/mirasim.so", "../mirasim.so", "/mirasim.so", "other.so", "mirasim.dll"):
            with self.subTest(name=name):
                self.write_archive("linux_amd64", [(name, b"fixture")])
                with self.assertRaisesRegex(ValueError, "ZIP root"):
                    verify_release(self.root, "v0.7.1")

    def test_rejects_multiple_libraries_and_extra_files(self):
        for extra in ("other.so", "mirasim.so", "README.md"):
            with self.subTest(extra=extra):
                self.write_archive("linux_amd64", [("mirasim.so", b"fixture"), (extra, b"extra")])
                with self.assertRaisesRegex(ValueError, "ZIP root"):
                    verify_release(self.root, "v0.7.1")

    def test_rejects_symlink(self):
        entry = zipfile.ZipInfo("mirasim.so")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_archive("linux_amd64", [(entry, b"target")])
        with self.assertRaisesRegex(ValueError, "regular file"):
            verify_release(self.root, "v0.7.1")

    def test_rejects_empty_library(self):
        self.write_archive("linux_amd64", [("mirasim.so", b"")])
        with self.assertRaisesRegex(ValueError, "empty"):
            verify_release(self.root, "v0.7.1")

    def test_submission_has_no_pinned_version(self):
        prepare_submission(self.root, "https://github.com/yescomputer/cpa-plugin-mirasim", "yescomputer", "v0.7.1")
        registry = json.loads((self.root / "registry.json").read_text())
        self.assertEqual(registry["schema_version"], 1)
        self.assertEqual(registry["plugins"][0]["id"], "mirasim")
        self.assertNotIn("version", registry["plugins"][0])
        body = (self.root / "store-pr.md").read_text()
        self.assertIn("Before submitting this draft", body)
        self.assertIn("/releases/download/v0.7.1/checksums.txt", body)

    def test_rejects_non_repository_urls(self):
        for url in ("http://github.com/user/repo", "https://github.com/user/repo/releases", "https://github.com/user/repo.git"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                prepare_submission(self.root, url, "author", "v0.7.1")


if __name__ == "__main__":
    unittest.main()
