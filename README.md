# Gentoo Auto Installer

`gentoo_autoinstaller_allfixes.sh` is an interactive Bash script that provisions a
fresh Gentoo Linux system on a selected disk. It aims to provide a repeatable
"all-in-one" install experience while still letting users pick key options such
as filesystems, init system, encryption mode, and desktop environment.

## Features
- **Stable-only profile** – `ACCEPT_KEYWORDS` is pinned to the stable
  architecture for a consistent system.
- **LUKS2 root with optional encrypted swap** – supports hibernation when swap is
  configured as a LUKS device.
- **Auto or manual partitioning** – choose between scripted `parted` based
  partitioning or dropping into `cfdisk` for manual layout.
- **UEFI or BIOS boot** – creates the right boot partitions and installs GRUB
  accordingly.
- **Selectable root filesystem** – `ext4` or `btrfs`.
- **OpenRC or systemd** – choose the desired init system.
- **Kernel options** – prebuilt binary kernel, source build, or genkernel with
  menuconfig; Dracut is used for the initramfs.
- **Optional KDE Plasma desktop** – installs Plasma and SDDM if requested.
- **NetworkManager support** – install and enable NetworkManager during setup.
- **Robust stage3 fetcher** – prefers minimal stage3 tarballs and falls back to
  other variants or mirror directory listings when necessary.
- **Idempotent “emerge” wrapper** – skips already-installed packages during
  inside-chroot steps.

## Usage
1. Boot into a Gentoo live environment (or any live system with required tools).
2. Clone this repository or download the script.
3. Run as root:
   ```bash
   bash gentoo_autoinstaller_allfixes.sh
   ```
4. Answer the interactive prompts. **The selected disk will be formatted**, so
   ensure important data is backed up.
5. When the script completes, unmount `/mnt/gentoo`, close LUKS mappings, and
   reboot into the new system.

## Notes
- The script requires common utilities such as `curl`, `wget`, `parted`,
  `sgdisk`, `cryptsetup`, `tar`, and others already present on Gentoo install
  media.
- By default SSL certificate verification is disabled for downloads. Consider
  answering "no" to the related prompt to keep secure defaults.
- SHA512 checks of the downloaded stage3 tarball are performed; warnings are
  printed if the verification fails.

Use this script at your own risk. Review the code and prompts carefully before
letting it modify your disks.
