"""Omarchy Server: what an install from a Server ISO (omarchy-iso-make
--server) adds to the target. The image already holds the Server package set;
this marks the edition, gives the passwordless owner sudo, and on an encrypted
install sets up the two ways the disk unlocks at boot: the TPM, bound to
PCR 7, where the machine has one, and SSH into the initramfs (port 2222)."""

from __future__ import annotations

import os
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
UNLOCK_NETWORK_UNIT = Path("etc/systemd/system/omarchy-ssh-unlock-network.service")
UNLOCK_DROPIN = Path("etc/mkinitcpio.conf.d/zz-omarchy-ssh-unlock.conf")
TPM_VERSION = Path("/sys/class/tpm/tpm0/tpm_version_major")

# The Omarchy code a server runs: a git checkout on Omarchy's dev channel, which
# omarchy update fast-forwards. The ISO carries it as a bundle, with the branch
# and the remote it tracks in checkout.env (omarchy-iso-make --server).
CHECKOUT_BUNDLE = SERVER_FILES / "checkout" / "omarchy.bundle"
CHECKOUT_ENV = SERVER_FILES / "checkout" / "checkout.env"
SYSTEM_SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/bin"


def is_server_iso(marker: Path = SERVER_MARKER) -> bool:
    return marker.is_file()


def write_edition(target: Path) -> None:
    """Before the runtime's own setup runs, which reads it and leaves it."""
    edition = target / "etc" / "omarchy" / "edition"
    edition.parent.mkdir(parents=True, exist_ok=True)
    edition.write_text("server\n")


def target_omarchy_path(ctx: InstallContext) -> Path:
    """Where the target's Omarchy code lives, as the target sees it: the
    package's tree on the desktop, the owner's checkout on a server."""
    if ctx.server:
        return Path("/home") / ctx.username / "omarchy"
    return Path("/usr/share/omarchy")


def _checkout_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition("=")
        if key in ("BRANCH", "URL") and value:
            values[key] = value
    if set(values) != {"BRANCH", "URL"}:
        raise RuntimeError(f"{path} must name BRANCH and URL")
    return values


def link_checkout(ctx: InstallContext) -> None:
    """Clone the ISO's checkout to ~/omarchy and link Omarchy to it the way
    omarchy-dev-link does: /etc/omarchy.conf names OMARCHY_PATH, and sudo
    resolves omarchy-* from the checkout's bin."""
    target = ctx.target
    username = ctx.username
    checkout = target_omarchy_path(ctx)
    env = _checkout_env(CHECKOUT_ENV)

    info(f"› cloning the Omarchy checkout ({env['BRANCH']}, tracking {env['URL']}) to {checkout}")
    staged = target / "var" / "tmp" / "omarchy.bundle"
    shutil.copy2(CHECKOUT_BUNDLE, staged)
    staged.chmod(0o644)
    try:
        user = ["arch-chroot", "-u", username, str(target)]
        subprocess.run([*user, "git", "clone", "--quiet", "--branch", env["BRANCH"],
                        "/var/tmp/omarchy.bundle", str(checkout)], check=True)
        # origin/<branch> stays from the bundle, so the branch keeps tracking
        # it; the next fetch, omarchy update's, goes to the fork.
        subprocess.run([*user, "git", "-C", str(checkout), "remote", "set-url", "origin", env["URL"]], check=True)
    finally:
        staged.unlink(missing_ok=True)

    conf = target / "etc" / "omarchy.conf"
    conf.write_text(f'export OMARCHY_PATH="{checkout}"\n')
    conf.chmod(0o644)
    sudoers = target / "etc" / "sudoers.d" / "omarchy-dev-path"
    sudoers.parent.mkdir(parents=True, exist_ok=True)
    sudoers.write_text(f'Defaults secure_path="{checkout}/bin:{SYSTEM_SECURE_PATH}"\n')
    sudoers.chmod(0o440)
    subprocess.run(["arch-chroot", str(target), "visudo", "-cf", "/etc/sudoers.d/omarchy-dev-path"], check=True)


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

    # A launcher's install (omarchy-install-unattended) pins the installed
    # system's host keys and may carry the installer's Tailscale node over.
    if keys_out := os.environ.get("OMARCHY_INSTALL_HOST_KEYS_OUT"):
        export_host_keys(target, Path(keys_out))
    if (state := os.environ.get("OMARCHY_INSTALL_TAILSCALE_STATE_DIR")) and Path(state).is_dir():
        carry_tailscale_state(target, Path(state))


def export_host_keys(target: Path, keys_out: Path) -> None:
    subprocess.run(["arch-chroot", str(target), "ssh-keygen", "-A"], check=True, capture_output=True)
    keys_out.mkdir(parents=True, exist_ok=True)
    published = sorted((target / "etc" / "ssh").glob("ssh_host_*_key.pub"))
    if not published:
        raise RuntimeError("ssh-keygen -A made no host keys on the target")
    for key in published:
        shutil.copy2(key, keys_out / key.name)
    # The SSH unlock's own key, so the launcher can pin it and type the
    # passphrase itself.
    unlock = target / UNLOCK_DIR / "dropbear_ed25519_host_key.pub"
    if unlock.is_file():
        shutil.copy2(unlock, keys_out / "unlock_ed25519.pub")
        published.append(keys_out / "unlock_ed25519.pub")
    info(f"› host keys for the launcher: {', '.join(key.name for key in published)}")


def carry_tailscale_state(target: Path, state: Path) -> None:
    """The node the installer joined as becomes the installed server."""
    dest = target / "var" / "lib" / "tailscale"
    dest.mkdir(parents=True, exist_ok=True)
    dest.chmod(0o700)
    shutil.copytree(state, dest, dirs_exist_ok=True)
    subprocess.run(["arch-chroot", str(target), "systemctl", "enable", "tailscaled.service"], check=True)
    info("› Tailscale state carried over from the installer")


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
                       ("omarchy-ssh-unlock-network.service", UNLOCK_NETWORK_UNIT),
                       ("zz-omarchy-ssh-unlock.conf", UNLOCK_DROPIN)):
        (target / dest).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(files / name, target / dest)

    host_key = Path("/") / UNLOCK_DIR / "dropbear_ed25519_host_key"
    (target / UNLOCK_DIR / host_key.name).unlink(missing_ok=True)
    result = subprocess.run(["arch-chroot", str(target), "dropbearkey", "-t", "ed25519", "-f", str(host_key)],
                            check=True, capture_output=True, text=True)
    fingerprint = next((line.split()[-1] for line in result.stdout.splitlines() if line.startswith("Fingerprint:")), "")
    public = next((line for line in result.stdout.splitlines() if line.startswith("ssh-ed25519 ")), "")
    if not public:
        raise RuntimeError("dropbearkey printed no public key for the SSH unlock")
    (target / UNLOCK_DIR / "dropbear_ed25519_host_key.pub").write_text(public + "\n")
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
