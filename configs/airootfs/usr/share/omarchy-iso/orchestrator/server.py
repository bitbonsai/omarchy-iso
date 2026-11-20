"""Omarchy Server: what an install from a Server ISO (omarchy-iso-make
--server) adds to the target. The image already holds the Server package set;
this marks the edition, gives the passwordless owner sudo, and on an encrypted
install sets up the two ways the disk unlocks at boot: the TPM, bound to
PCR 7, where the machine has one, and SSH into the initramfs (port 2222)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .context import InstallContext
from .ui import info

SERVER_MARKER = Path("/usr/share/omarchy-iso/server-install")
SERVER_FILES = Path("/usr/share/omarchy-iso/server")

UNLOCK_DIR = Path("etc/omarchy/ssh-unlock")
UNLOCK_HOOK = Path("etc/initcpio/install/omarchy-ssh-unlock")
UNLOCK_UNIT = Path("etc/systemd/system/omarchy-ssh-unlock.service")
UNLOCK_DROPIN = Path("etc/mkinitcpio.conf.d/zz-omarchy-ssh-unlock.conf")
TPM_VERSION = Path("/sys/class/tpm/tpm0/tpm_version_major")


def is_server_iso(marker: Path = SERVER_MARKER) -> bool:
    return marker.is_file()


def write_edition(target: Path) -> None:
    """Before the runtime's own setup runs, which reads it and leaves it."""
    edition = target / "etc" / "omarchy" / "edition"
    edition.parent.mkdir(parents=True, exist_ok=True)
    edition.write_text("server\n")


def initramfs_has_ssh_unlock(target: Path) -> bool:
    """The pre-built UKI has no SSH unlock; such a target builds its own."""
    return (target / UNLOCK_DROPIN).is_file()


def configure_server(ctx: InstallContext) -> None:
    target = ctx.target
    username = ctx.username

    # The runtime's Server setup writes this rule. The owner has no password,
    # so without it they could never sudo: write it when the runtime did not.
    sudoers = target / "etc" / "sudoers.d" / "omarchy-server-owner"
    if not sudoers.exists():
        info(f"› passwordless sudo for {username}")
        sudoers.parent.mkdir(parents=True, exist_ok=True)
        sudoers.write_text(f"{username} ALL=(ALL:ALL) NOPASSWD: ALL\n")
        sudoers.chmod(0o440)
        subprocess.run(["arch-chroot", str(target), "visudo", "-cf", "/etc/sudoers.d/omarchy-server-owner"], check=True)
    info("› locking root")
    subprocess.run(["arch-chroot", str(target), "passwd", "-l", "root"], check=True, capture_output=True)

    if ctx.encrypt:
        stage_ssh_unlock(ctx)
        enroll_tpm(ctx)


def stage_ssh_unlock(ctx: InstallContext) -> None:
    from .phases_impl import _authorized_keys

    files = SERVER_FILES
    target = ctx.target
    if ctx.authorized_keys_path is None:
        raise RuntimeError("an encrypted Server install needs authorized_keys for the SSH unlock")
    keys = _authorized_keys(ctx.authorized_keys_path)

    unlock = target / UNLOCK_DIR
    unlock.mkdir(parents=True, exist_ok=True)
    unlock.chmod(0o700)
    (unlock / "authorized_keys").write_text("".join(f"{key}\n" for key in keys))
    (unlock / "authorized_keys").chmod(0o600)
    shutil.copy2(files / "omarchy-unlock", unlock / "omarchy-unlock")
    for name, dest in (("omarchy-ssh-unlock.install", UNLOCK_HOOK),
                       ("omarchy-ssh-unlock.service", UNLOCK_UNIT),
                       ("zz-omarchy-ssh-unlock.conf", UNLOCK_DROPIN)):
        (target / dest).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(files / name, target / dest)

    host_key = Path("/") / UNLOCK_DIR / "dropbear_ed25519_host_key"
    (target / UNLOCK_DIR / host_key.name).unlink(missing_ok=True)
    result = subprocess.run(["arch-chroot", str(target), "dropbearkey", "-t", "ed25519", "-f", str(host_key)],
                            check=True, capture_output=True, text=True)
    fingerprint = next((line.split()[-1] for line in result.stdout.splitlines() if line.startswith("Fingerprint:")), "")
    info(f"› SSH unlock on port 2222, host key {fingerprint}")


def has_tpm2(version: Path = TPM_VERSION) -> bool:
    try:
        return version.read_text().strip() == "2"
    except OSError:
        return False


def _luks_device(target: Path) -> str:
    """The LUKS partition under the target's root mapper."""
    source = subprocess.run(["findmnt", "-no", "SOURCE", str(target)],
                            check=True, capture_output=True, text=True).stdout.strip().split("[")[0]
    if not source.startswith("/dev/mapper/"):
        raise RuntimeError(f"encrypted install, but {target} is on {source}, not a LUKS mapper")
    status = subprocess.run(["cryptsetup", "status", source.removeprefix("/dev/mapper/")],
                            check=True, capture_output=True, text=True).stdout
    for line in status.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "device":
            return value.strip()
    raise RuntimeError(f"cryptsetup status {source} names no device")


def enroll_tpm(ctx: InstallContext) -> None:
    """Bind a TPM2 key slot to PCR 7 (the Secure Boot state), which the
    installed system measures the same as this live boot. A failure leaves
    the passphrase as the only way in, which SSH unlock covers, so it is
    logged and the install goes on."""
    if not has_tpm2():
        info("› no TPM 2.0: the disk unlocks with the passphrase over SSH")
        return

    from .phases_impl import _provision_encryption_password
    password = _provision_encryption_password(ctx)
    if not password:
        raise RuntimeError("encrypted Server install without a passphrase to enroll the TPM with")

    device = _luks_device(ctx.target)
    key = ctx.state_dir / "tpm-enroll.key"
    key.touch(mode=0o600)
    key.chmod(0o600)
    try:
        key.write_text(password)
        result = subprocess.run(
            ["systemd-cryptenroll", f"--unlock-key-file={key}", "--tpm2-device=auto", "--tpm2-pcrs=7", device],
            capture_output=True, text=True,
        )
    finally:
        key.unlink(missing_ok=True)
    if result.returncode == 0:
        info(f"› TPM2 enrolled for {device} (PCR 7)")
    else:
        info(f"› WARNING: TPM2 enrollment failed, the disk unlocks over SSH: {result.stderr.strip()}")
