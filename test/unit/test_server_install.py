"""Unit tests for the Omarchy Server install: the context's checks, the
phase list, and configure_server against a temp target with subprocess
mocked out."""

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

SHARE = Path(__file__).resolve().parents[2] / "configs/airootfs/usr/share/omarchy-iso"
sys.path.insert(0, str(SHARE))

sys.modules.setdefault(
    "orchestrator.archinstall_adapter", types.ModuleType("orchestrator.archinstall_adapter")
)

from orchestrator import server  # noqa: E402
from orchestrator.context import InstallContext  # noqa: E402

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHR9zv9djS6CgUFXF1bpbUOIs81q8/7sUZdUsbIdH1G6 owner@laptop"


class ServerContextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        (self.dir / "user_configuration.json").write_text(json.dumps({"disk_config": {}}))
        self.creds = self.dir / "user_credentials.json"
        self.keys = self.dir / "authorized_keys"
        self.env = {
            "OMARCHY_INSTALL_CONFIG": str(self.dir / "user_configuration.json"),
            "OMARCHY_INSTALL_CREDS": str(self.creds),
            "OMARCHY_INSTALL_STATE_DIR": str(self.dir / "state"),
            "OMARCHY_INSTALL_AUTHORIZED_KEYS_FILE": str(self.keys),
        }

    def context(self, *, server_iso=True):
        with mock.patch.dict(os.environ, self.env), \
                mock.patch.object(server, "is_server_iso", return_value=server_iso):
            return InstallContext.from_env()

    def test_a_server_install_needs_the_owner_and_their_keys(self):
        self.creds.write_text(json.dumps({"users": [{"username": "owner", "enc_password": "*", "sudo": True}]}))
        with self.assertRaisesRegex(RuntimeError, "authorized_keys"):
            self.context()
        self.keys.write_text(KEY + "\n")
        self.assertTrue(self.context().server)

        self.creds.write_text(json.dumps({"users": []}))
        with self.assertRaisesRegex(RuntimeError, "owner"):
            self.context()

    def test_a_desktop_iso_is_not_a_server(self):
        self.creds.write_text(json.dumps({"users": [{"username": "owner", "enc_password": "x", "sudo": True}]}))
        self.assertFalse(self.context(server_iso=False).server)


class ServerPhasesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / "target"
        self.target.mkdir()
        keys = Path(self.tmp.name) / "authorized_keys"
        keys.write_text(KEY + "\n")
        self.ctx = types.SimpleNamespace(
            target=self.target, server=True, encrypt=True, username="owner", defer_provisioning=False,
            authorized_keys_path=keys, state_dir=Path(self.tmp.name), oem_dir=None,
            user_configuration={"disk_config": {"disk_encryption": {"encryption_password": "hunter22"}}},
            user_credentials={}, omarchy_install={}, state={},
        )
        self.calls = []
        patcher = mock.patch.object(server, "SERVER_FILES", SHARE / "server")
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_run(self, cmd, **kwargs):
        self.calls.append(cmd)
        if cmd[:1] == ["findmnt"]:
            return CompletedProcess(cmd, 0, "/dev/mapper/root[/@]\n", "")
        if cmd[:1] == ["cryptsetup"]:
            return CompletedProcess(cmd, 0, "  type:    LUKS2\n  device:  /dev/vda2\n", "")
        if cmd[:1] == ["systemd-cryptenroll"]:
            key = Path(next(arg for arg in cmd if arg.startswith("--unlock-key-file=")).split("=", 1)[1])
            self.enrolled_with = key.read_text()
            self.enrolled_mode = key.stat().st_mode & 0o777
            return CompletedProcess(cmd, 0, "", "")
        if "dropbearkey" in cmd:
            return CompletedProcess(cmd, 0, "Public key...\nFingerprint: SHA256:abc\n", "")
        return CompletedProcess(cmd, 0, "", "")

    def test_the_phase_comes_before_the_uki_is_built_and_only_on_server(self):
        from orchestrator import main

        names = [name for name, _ in main.build_phases(self.ctx)]
        self.assertLess(names.index("Configuring Server"), names.index("Finalizing boot and user"))
        self.assertLess(names.index("Linking the Omarchy checkout"), names.index("Configuring system"))
        self.ctx.server = False
        self.assertNotIn("Configuring Server", [name for name, _ in main.build_phases(self.ctx)])

    def test_an_encrypted_server_gets_sudo_the_ssh_unlock_and_a_pcr7_tpm_slot(self):
        with mock.patch("subprocess.run", side_effect=self.fake_run), \
                mock.patch.object(server, "has_tpm2", return_value=True):
            server.configure_server(self.ctx)

        sudoers = self.target / "etc/sudoers.d/omarchy-server-owner"
        self.assertEqual(sudoers.read_text(), "owner ALL=(ALL:ALL) NOPASSWD: ALL\n")
        self.assertEqual(sudoers.stat().st_mode & 0o777, 0o440)
        self.assertIn(["arch-chroot", str(self.target), "passwd", "-l", "root"], self.calls)

        unlock = self.target / "etc/omarchy/ssh-unlock"
        self.assertEqual((unlock / "authorized_keys").read_text(), KEY + "\n")
        self.assertTrue((self.target / "etc/initcpio/install/omarchy-ssh-unlock").is_file())
        self.assertTrue((self.target / "etc/systemd/system/omarchy-ssh-unlock.service").is_file())
        self.assertTrue(server.initramfs_has_ssh_unlock(self.target))

        enroll = next(cmd for cmd in self.calls if cmd[0] == "systemd-cryptenroll")
        self.assertIn("--tpm2-pcrs=7", enroll)
        self.assertEqual(enroll[-1], "/dev/vda2")
        self.assertEqual(self.enrolled_with, "hunter22")
        self.assertEqual(self.enrolled_mode, 0o600)
        self.assertFalse(list(Path(self.tmp.name).glob("tpm-enroll.key")))

    def test_without_a_tpm_the_ssh_unlock_is_the_way_in(self):
        with mock.patch("subprocess.run", side_effect=self.fake_run), \
                mock.patch.object(server, "has_tpm2", return_value=False):
            server.configure_server(self.ctx)
        self.assertFalse(any(cmd[0] == "systemd-cryptenroll" for cmd in self.calls))
        self.assertTrue(server.initramfs_has_ssh_unlock(self.target))

    def test_an_unencrypted_server_gets_no_unlock(self):
        self.ctx.encrypt = False
        with mock.patch("subprocess.run", side_effect=self.fake_run):
            server.configure_server(self.ctx)
        self.assertFalse(server.initramfs_has_ssh_unlock(self.target))
        self.assertTrue((self.target / "etc/sudoers.d/omarchy-server-owner").is_file())

    def test_the_runtimes_sudo_rule_is_left_alone(self):
        sudoers = self.target / "etc/sudoers.d/omarchy-server-owner"
        sudoers.parent.mkdir(parents=True)
        sudoers.write_text("from the runtime\n")
        self.ctx.encrypt = False
        with mock.patch("subprocess.run", side_effect=self.fake_run):
            server.configure_server(self.ctx)
        self.assertEqual(sudoers.read_text(), "from the runtime\n")

    def test_the_edition_is_server(self):
        server.write_edition(self.target)
        self.assertEqual((self.target / "etc/omarchy/edition").read_text(), "server\n")


class LinkCheckoutTest(unittest.TestCase):
    """link_checkout clones the ISO's bundle with real git; arch-chroot is
    replaced by running the command with its paths under the target."""

    def setUp(self):
        import subprocess
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        source = root / "source"
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run([*git, "init", "-q", "-b", "server", str(source)], check=True)
        (source / "bin").mkdir()
        (source / "bin" / "omarchy-version").write_text("#!/bin/sh\n")
        subprocess.run([*git, "-C", str(source), "add", "."], check=True)
        subprocess.run([*git, "-C", str(source), "commit", "-qm", "init"], check=True)
        subprocess.run([*git, "-C", str(source), "tag", "v4.5.0"], check=True)
        files = root / "iso" / "checkout"
        files.mkdir(parents=True)
        subprocess.run(["git", "-C", str(source), "bundle", "create", "-q", str(files / "omarchy.bundle"),
                        "--tags", "server"], check=True)
        (files / "checkout.env").write_text("BRANCH=server\nURL=https://github.com/example/omarchy.git\n")
        for name, value in (("CHECKOUT_BUNDLE", files / "omarchy.bundle"), ("CHECKOUT_ENV", files / "checkout.env")):
            patcher = mock.patch.object(server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.target = root / "target"
        (self.target / "var/tmp").mkdir(parents=True)
        (self.target / "home/owner").mkdir(parents=True)
        (self.target / "etc").mkdir()
        self.ctx = types.SimpleNamespace(target=self.target, server=True, username="owner")
        self.real_run = subprocess.run

    def fake_run(self, cmd, **kwargs):
        if cmd[0] != "arch-chroot":
            return self.real_run(cmd, **kwargs)
        if "visudo" in cmd:
            return CompletedProcess(cmd, 0, "", "")
        inner = cmd[4:] if cmd[1] == "-u" else cmd[2:]
        inner = [str(self.target) + arg if arg.startswith(("/home/", "/var/tmp/")) else arg for arg in inner]
        return self.real_run(inner, **kwargs)

    def test_the_checkout_is_cloned_tracks_the_fork_and_is_linked(self):
        import subprocess
        with mock.patch("subprocess.run", side_effect=self.fake_run):
            server.link_checkout(self.ctx)

        checkout = self.target / "home/owner/omarchy"
        git = lambda *args: self.real_run(["git", "-C", str(checkout), *args],
                                          capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(git("rev-parse", "--abbrev-ref", "HEAD"), "server")
        self.assertEqual(git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"), "origin/server")
        self.assertEqual(git("remote", "get-url", "origin"), "https://github.com/example/omarchy.git")
        self.assertEqual(git("describe", "--tags"), "v4.5.0")
        self.assertEqual((self.target / "etc/omarchy.conf").read_text(), 'export OMARCHY_PATH="/home/owner/omarchy"\n')
        self.assertEqual((self.target / "etc/sudoers.d/omarchy-dev-path").read_text(),
                         'Defaults secure_path="/home/owner/omarchy/bin:/usr/local/sbin:/usr/local/bin:/usr/bin"\n')
        self.assertFalse((self.target / "var/tmp/omarchy.bundle").exists())

    def test_the_desktop_keeps_the_package_tree(self):
        self.ctx.server = False
        self.assertEqual(server.target_omarchy_path(self.ctx), Path("/usr/share/omarchy"))


class UnlockHooksTest(unittest.TestCase):
    """zz-omarchy-ssh-unlock.conf turns Omarchy's busybox baseline into the
    systemd one with the SSH unlock in front of sd-encrypt."""

    def hooks(self, baseline):
        import subprocess
        script = f"HOOKS=({baseline})\nsource {SHARE / 'server/zz-omarchy-ssh-unlock.conf'}\necho \"${{HOOKS[*]}}\""
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout.split()

    def test_busybox_baseline(self):
        hooks = self.hooks("base udev plymouth keyboard autodetect microcode modconf kms keymap consolefont block encrypt filesystems fsck")
        self.assertEqual(hooks, "base systemd keyboard autodetect microcode modconf kms sd-vconsole block omarchy-ssh-unlock sd-encrypt filesystems fsck".split())

    def test_already_systemd_is_kept_once(self):
        hooks = self.hooks("base systemd keyboard sd-vconsole block omarchy-ssh-unlock sd-encrypt filesystems")
        self.assertEqual(hooks.count("omarchy-ssh-unlock"), 1)
        self.assertLess(hooks.index("omarchy-ssh-unlock"), hooks.index("sd-encrypt"))


if __name__ == "__main__":
    unittest.main()
