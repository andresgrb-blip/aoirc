import configparser
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from packaging.build_deb import build_package


class DebianPackageTests(unittest.TestCase):
    def test_installable_layout_dependencies_and_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = build_package(Path(tmp), "0.1.0")
            members = subprocess.check_output(["ar", "-t", str(path)], text=True).splitlines()
            self.assertEqual(members, ["debian-binary", "control.tar.gz", "data.tar.gz"])
            self.assertEqual(
                subprocess.check_output(["ar", "-p", str(path), "debian-binary"]), b"2.0\n"
            )
            control_bytes = subprocess.check_output(["ar", "-p", str(path), "control.tar.gz"])
            data_bytes = subprocess.check_output(["ar", "-p", str(path), "data.tar.gz"])
            with tarfile.open(fileobj=io.BytesIO(control_bytes), mode="r:gz") as control:
                metadata = control.extractfile("./control").read().decode()
                self.assertIn("Architecture: all\n", metadata)
                self.assertIn("Depends: python3 (>= 3.10), python3-tk, ca-certificates\n", metadata)
                checksums = control.extractfile("./md5sums").read().decode().splitlines()
            with tarfile.open(fileobj=io.BytesIO(data_bytes), mode="r:gz") as data:
                self.assertEqual(data.getmember("./usr/bin/aoirc").mode, 0o755)
                for entry in data.getmembers():
                    self.assertEqual((entry.uid, entry.gid), (0, 0))
                    self.assertFalse(entry.mode & 0o022)
                for line in checksums:
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.md5(data.extractfile(f"./{name}").read()).hexdigest(), digest)
                self.assertFalse(any("config.json" in name for name in data.getnames()))
                desktop = configparser.ConfigParser(interpolation=None)
                desktop.read_string(data.extractfile("./usr/share/applications/aoirc.desktop").read().decode())
                self.assertEqual(desktop["Desktop Entry"]["Exec"], "/usr/bin/aoirc")
                self.assertFalse(desktop["Desktop Entry"].getboolean("Terminal"))
                launcher = data.extractfile("./usr/bin/aoirc").read().decode()
                self.assertIn('exec /usr/bin/python3 -I -B /usr/share/aoirc/ui.py "$@"', launcher)
                compile(data.extractfile("./usr/share/aoirc/ui.py").read(), "ui.py", "exec")
            checksum = path.with_suffix(".deb.sha256").read_text().split()[0]
            self.assertEqual(checksum, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_build_is_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = build_package(root / "first", "0.1.0", 1234567890).read_bytes()
            second = build_package(root / "second", "0.1.0", 1234567890).read_bytes()
            self.assertEqual(first, second)

    def test_rejects_invalid_version_and_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                build_package(Path(tmp), "0.1.0\nDepends: anything")
            with self.assertRaises(ValueError):
                build_package(Path(tmp), "0.1.0", -1)


if __name__ == "__main__":
    unittest.main()
