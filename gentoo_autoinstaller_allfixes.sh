#!/usr/bin/env bash
# Gentoo All-in-One Installer (rev-0808e)
# - Stable branch enforced (ACCEPT_KEYWORDS set to stable arch)
# - Auto-accept all licenses option (default: yes)
# - /boot unencrypted (UEFI FAT32 or BIOS ext4)
# - LUKS2 root + optional LUKS swap (hibernate)
# - Kernel -> Dracut
# - Optional KDE Plasma + SDDM
# - rsync probe + fallback to webrsync
# - Robust stage3 finder
# - Safer proc mount, UUID settle, MAKEOPTS expansion

set -Eeuo pipefail

# ---- emerge idempotent wrapper ----
# Skips already-installed atoms and adds --noreplace for plain installs.
if [ -z "${EMERGE_WRAPPER_LOADED:-}" ]; then
  EMERGE_WRAPPER_LOADED=1
  emerge() {
    local _real_emerge; _real_emerge=$(command -v emerge)
    local args=("$@"); local pass_through=0
    for a in "${args[@]}"; do
      case "$a" in
        --sync|--metadata|--depclean|-c|--prune|--unmerge|-C|--deselect|@world|@system|@preserved-rebuild)
          pass_through=1; break;;
      esac
    done
    if [ $pass_through -eq 0 ]; then
      for a in "${args[@]}"; do
        case "$a" in -u|--update|-U|--changed-use|--newuse|-D|--deep) pass_through=1; break;; esac
      done
    fi
    if [ $pass_through -eq 1 ]; then command "$_real_emerge" "$@"; return $?; fi
    local opts=(); local atoms=()
    for a in "${args[@]}"; do case "$a" in -*|@*) opts+=("$a");; *) atoms+=("$a");; esac; done
    if [ "${#atoms[@]}" -eq 0 ]; then command "$_real_emerge" "$@"; return $?; fi
    local to_install=()
    for atom in "${atoms[@]}"; do
      if portageq has_version / "$atom" >/dev/null 2>&1; then
        printf '[skip] %s already installed\n' "$atom" >&2
      else to_install+=("$atom"); fi
    done
    if [ "${#to_install[@]}" -eq 0 ]; then printf '[ok] All requested packages already present\n' >&2; return 0; fi
    printf '[emerge] Installing: %s\n' "${to_install[*]}" >&2
    command "$_real_emerge" --noreplace "${opts[@]}" "${to_install[@]}"
  }
fi
# ---- end emerge idempotent wrapper ----


# ---------- helpers ----------
err(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || err "Missing: $1"; }
title(){ printf "\n==== %s ====\n" "$*"; }
yn(){ local p="$1" d="${2:-Y}" a; read -rp "$p [Y/n] " a || true; a="${a:-$d}"; [[ "$a" =~ ^[Yy]$ ]]; }
ask(){ local p="$1" v; read -rp "$p: " v; echo "$v"; }
askd(){ local p="$1" d="$2" v; read -rp "$p [$d]: " v || true; echo "${v:-$d}"; }
ask_secret(){ local p="$1" v1 v2; while :; do read -rsp "$p: " v1; echo; read -rsp "Confirm: " v2; echo; [[ "$v1" == "$v2" ]] && { echo -n "$v1"; return; }; echo "Mismatch, try again."; done; }
partsfx(){ [[ "$1" =~ (nvme|mmcblk|loop) ]] && echo p || echo; }  # /dev/nvme0n1p1 vs /dev/sda1

# ---------- sanity ----------
need lsblk; need sed; need awk; need grep; need curl; need wget
need parted; need cfdisk; need sgdisk
need cryptsetup; need mkfs.vfat; need mkfs.ext4; need mkswap
need tar; need sha512sum

[[ $EUID -eq 0 ]] || err "Run as root."
[[ -d /sys/firmware/efi ]] && DEFAULT_BOOTMODE="UEFI" || DEFAULT_BOOTMODE="BIOS"

# Arch (for stage3 + keywords)
case "$(uname -m)" in
  x86_64) G_ARCH="amd64"; KW_ARCH="amd64" ;;
  aarch64|arm64) G_ARCH="arm64"; KW_ARCH="arm64" ;;
  *) G_ARCH="amd64"; KW_ARCH="amd64" ;;
esac

title "Disk selection"
lsblk -dpno NAME,SIZE,MODEL,TYPE | awk '$4=="disk" || NR==1'
DISK="$(ask "Enter target DISK (e.g., /dev/nvme0n1 or /dev/sda)")"
[[ -b "$DISK" ]] || err "Not a block device: $DISK"
PSFX="$(partsfx "$DISK")"

title "Boot mode / FS / Init"
BOOTMODE=$(askd "Boot mode (UEFI/BIOS)" "$DEFAULT_BOOTMODE"); BOOTMODE=$(echo "$BOOTMODE" | tr '[:lower:]' '[:upper:]')
[[ "$BOOTMODE" =~ ^(UEFI|BIOS)$ ]] || err "Boot mode must be UEFI or BIOS"
ROOT_FS=$(askd "Root filesystem (ext4/btrfs)" "ext4"); [[ "$ROOT_FS" =~ ^(ext4|btrfs)$ ]] || err "Unsupported root FS"
INIT_SYS=$(askd "Init system (openrc/systemd)" "openrc"); INIT_SYS=$(echo "$INIT_SYS" | tr '[:upper:]' '[:lower:]'); [[ "$INIT_SYS" =~ ^(openrc|systemd)$ ]] || err "Init must be openrc or systemd"

# Partitioning method
title "Partitioning method"
echo "Choose:"
echo "  auto          : script partitions the disk (parted)"
echo "  manual-cfdisk : YOU run cfdisk, then we continue"
PART_MODE=$(askd "Partitioning method (auto/manual-cfdisk)" "manual-cfdisk")

BOOT_SIZE=""; ROOT_SIZE=""; SWAP_SIZE=""
if [[ "$PART_MODE" == "auto" ]]; then
  title "Partition sizes (auto)"
  [[ "$BOOTMODE" == "UEFI" ]] && BOOT_SZ_DEFAULT="512MiB" || BOOT_SZ_DEFAULT="1GiB"
  BOOT_SIZE=$(askd "Boot partition size (e.g., 512MiB)" "$BOOT_SZ_DEFAULT")
  ROOT_SIZE=$(askd "Root size (e.g., 100GiB). 'rest' = all remaining minus swap" "rest")
  SWAP_SIZE=$(askd "Swap size (e.g., 16GiB)" "16GiB")
else
  echo "We'll launch cfdisk. Create:"
  if [[ "$BOOTMODE" == "UEFI" ]]; then
    echo "  - ESP (/boot) ~512MiB, type: EFI System"
  else
    echo "  - bios_grub 2MiB (type: BIOS boot)"
    echo "  - /boot ext4 ~1GiB"
  fi
  echo "  - root (LUKS)"
  echo "  - swap"
fi

title "Encryption & swap"
echo "Root = LUKS2."
echo "Swap:"
echo "  luks  : persistent key (hibernate OK)"
echo "  plain : random key each boot (no hibernate)"
SWAP_MODE=$(askd "Swap mode (luks/plain)" "plain"); [[ "$SWAP_MODE" =~ ^(luks|plain)$ ]] || err "Swap mode must be luks or plain"
if [[ "$SWAP_MODE" == "luks" ]]; then WANT_HIB="yes"; else WANT_HIB=$(askd "Configure hibernation (resume=)?" "no"); fi

title "System details"
HOSTNAME=$(askd "Hostname" "gentoo")
TIMEZONE=$(askd "Timezone" "America/New_York")
LOCALE=$(askd "Locale line for /etc/locale.gen" "en_US.UTF-8 UTF-8")

CREATE_USER=$(askd "Create a non-root user?" "yes")
if [[ "$CREATE_USER" =~ ^[Yy] ]]; then NEWUSER=$(askd "Username" "alex"); USER_PW=$(ask_secret "Password for $NEWUSER"); fi
ROOT_PW=$(ask_secret "Root password (system)")

title "CPU microcode"
CPU_VENDOR=$(grep -m1 -i '^vendor_id' /proc/cpuinfo | awk '{print $3}')
case "$CPU_VENDOR" in
  GenuineIntel) MICRO="intel-microcode" ;;
  AuthenticAMD) MICRO="amd-ucode" ;;
  *) MICRO=$(askd "Unknown vendor. Microcode package" "intel-microcode") ;;
esac

title "Kernel choice"
echo "1) gentoo-kernel-bin (prebuilt)"
echo "2) gentoo-sources (auto build)"
echo "3) gentoo-sources (interactive menuconfig via genkernel; Dracut still used)"
KSEL=$(askd "Kernel option (1/2/3)" "1")

title "Desktop"
PLASMA=$(askd "Install KDE Plasma + SDDM?" "no")
if [[ "$PLASMA" =~ ^[Yy] ]]; then
  SESSION=$(askd "Session (x11/wayland)" "x11"); [[ "$SESSION" =~ ^(x11|wayland)$ ]] || err "Session must be x11 or wayland"
else
  SESSION="x11"
fi

title "Network"
NM_INSTALL=$(askd "Install and enable NetworkManager?" "yes")

# Licenses
title "Licenses"
AUTO_LICENSES=$(askd "Auto-accept ALL package licenses (includes redistributable firmware, EULAs, etc.)?" "yes")

# Download/SSL options (global)
title "Download/SSL options"
INSECURE_ALL=$(askd "Disable SSL verification for ALL web requests (curl, wget, Portage)?" "yes")
CURL_OPTS=(-fsSL)
WGET_OPTS=(-q --show-progress)
if [[ "$INSECURE_ALL" =~ ^[Yy] ]]; then
  CURL_OPTS+=(-k)
  WGET_OPTS+=(--no-check-certificate)
fi

echo
echo "Summary:"
echo "  Disk:        $DISK ($BOOTMODE)"
echo "  Part mode:   $PART_MODE"
[[ "$PART_MODE" == "auto" ]] && { echo "  /boot: $BOOT_SIZE  root: $ROOT_SIZE  swap: $SWAP_SIZE"; } || echo "  You will select partitions after cfdisk"
echo "  Root FS:     $ROOT_FS"
echo "  Swap mode:   $SWAP_MODE (hib=$WANT_HIB)"
echo "  Init:        $INIT_SYS"
echo "  Desktop:     Plasma=$PLASMA ($SESSION)"
[[ "${NEWUSER:-}" ]] && echo "  User:        $NEWUSER"
echo "  Microcode:   $MICRO"
echo "  Kernel:      $KSEL (1=bin, 2=auto, 3=menuconfig)"
echo "  NetworkMgr:  $NM_INSTALL"
echo "  Licenses:    Auto-accept=${AUTO_LICENSES}"
echo "  Insecure web: $INSECURE_ALL"
echo
yn "Proceed? THIS MAY FORMAT PARTITIONS." || exit 1

# ---------- network check ----------
title "Network check"
ping -c1 distfiles.gentoo.org >/dev/null 2>&1 || err "No internet."

# ---------- partitioning ----------
BOOT_PART=""; ROOT_PART=""; SWAP_PART=""
if [[ "$PART_MODE" == "auto" ]]; then
  title "Partitioning $DISK (auto)"
  wipefs -af "$DISK"
  sgdisk --zap-all "$DISK" || true
  parted -s "$DISK" mklabel gpt

  if [[ "$BOOTMODE" == "UEFI" ]]; then
    parted -s "$DISK" mkpart ESP fat32 1MiB "$BOOT_SIZE"
    parted -s "$DISK" set 1 esp on
    if [[ "$ROOT_SIZE" == "rest" ]]; then
      parted -s "$DISK" mkpart primary "$BOOT_SIZE" "-$SWAP_SIZE"
    else
      parted -s "$DISK" mkpart primary "$BOOT_SIZE" "+$ROOT_SIZE"
      parted -s "$DISK" mkpart primary "-$SWAP_SIZE" 100%
    fi
    BOOT_PART="${DISK}${PSFX}1"; ROOT_PART="${DISK}${PSFX}2"; SWAP_PART="${DISK}${PSFX}3"
  else
    parted -s "$DISK" mkpart biosboot 1MiB 3MiB
    parted -s "$DISK" set 1 bios_grub on
    parted -s "$DISK" mkpart boot ext4 3MiB "$BOOT_SIZE"
    parted -s "$DISK" set 2 boot on
    if [[ "$ROOT_SIZE" == "rest" ]]; then
      parted -s "$DISK" mkpart primary "$BOOT_SIZE" "-$SWAP_SIZE"
    else
      parted -s "$DISK" mkpart primary "$BOOT_SIZE" "+$ROOT_SIZE"
      parted -s "$DISK" mkpart primary "-$SWAP_SIZE" 100%
    fi
    BOOT_PART="${DISK}${PSFX}2"; ROOT_PART="${DISK}${PSFX}3"; SWAP_PART="${DISK}${PSFX}4"
  fi
  partprobe "$DISK"; sleep 2
else
  title "Manual partitioning with cfdisk"
  echo "Launching cfdisk on $DISK..."
  read -rp "Press Enter to start cfdisk..." _
  cfdisk "$DISK"
  title "Select your partitions"
  lsblk -o NAME,SIZE,TYPE,FSTYPE,PARTTYPE,PARTLABEL,MOUNTPOINT "$DISK"
  echo
  BOOT_PART="$(ask "Enter /boot partition (e.g., /dev/sda1 or /dev/nvme0n1p1)")"
  ROOT_PART="$(ask "Enter ROOT  partition (e.g., /dev/sda2)")"
  SWAP_PART="$(ask "Enter SWAP  partition (e.g., /dev/sda3)")"
  for P in "$BOOT_PART" "$ROOT_PART" "$SWAP_PART"; do [[ -b "$P" ]] || err "Not a block device: $P"; done
  echo
  echo "About to FORMAT:"
  echo "  /boot -> $BOOT_PART"
  echo "  root  -> $ROOT_PART (LUKS)"
  echo "  swap  -> $SWAP_PART ($SWAP_MODE)"
  yn "Continue and FORMAT these partitions?" || exit 1
  wipefs -af "$BOOT_PART" || true
  wipefs -af "$ROOT_PART" || true
  wipefs -af "$SWAP_PART" || true
fi

# ---------- /boot format ----------
title "Formatting /boot"
if [[ "$BOOTMODE" == "UEFI" ]]; then
  mkfs.vfat -F32 -n EFI "$BOOT_PART"
else
  mkfs.ext4 -F -L boot "$BOOT_PART"
fi

# ---------- LUKS root ----------
title "Encrypting root with LUKS2"
ROOT_PW_LUKS=$(ask_secret "Enter LUKS passphrase for root (asked at boot)")
printf '%s' "$ROOT_PW_LUKS" | cryptsetup luksFormat --type luks2 --batch-mode --key-file - "$ROOT_PART"
printf '%s' "$ROOT_PW_LUKS" | cryptsetup open --key-file - "$ROOT_PART" cryptroot

# ---------- root filesystem ----------
title "Creating root filesystem ($ROOT_FS)"
if [[ "$ROOT_FS" == "ext4" ]]; then
  mkfs.ext4 -L root /dev/mapper/cryptroot
else
  mkfs.btrfs -L root /dev/mapper/cryptroot
fi

# ---------- swap ----------
title "Setting up swap ($SWAP_MODE)"
if [[ "$SWAP_MODE" == "luks" ]]; then
  printf '%s' "$ROOT_PW_LUKS" | cryptsetup luksFormat --type luks2 --batch-mode --key-file - "$SWAP_PART"
  printf '%s' "$ROOT_PW_LUKS" | cryptsetup open --key-file - "$SWAP_PART" cryptswap
  mkswap -L swap /dev/mapper/cryptswap
fi

# ---------- mount target ----------
title "Mounting target"
mkdir -p /mnt/gentoo
mount /dev/mapper/cryptroot /mnt/gentoo
mkdir -p /mnt/gentoo/boot
mount "$BOOT_PART" /mnt/gentoo/boot

# ---------- stage3 ----------
title "Fetching stage3 ($INIT_SYS)"
BASE_URL="https://distfiles.gentoo.org/releases/${G_ARCH}/autobuilds"
TXT_PRIMARY="latest-stage3-${G_ARCH}-${INIT_SYS}.txt"
TXT_FALLBACK="latest-stage3-${G_ARCH}.txt"
_extract_stage3_from_txt(){ grep -Eo '^[0-9]{8}T[0-9]{6}Z/stage3-[^[:space:]]+\.tar\.xz' || grep -Eo '[0-9]{8}T[0-9]{6}Z/stage3-[^[:space:]]+\.tar\.xz'; }
LATEST=""
if content="$(curl "${CURL_OPTS[@]}" -m 25 --retry 3 --retry-delay 2 "${BASE_URL}/${TXT_PRIMARY}" 2>/dev/null || true)"; then
  LATEST="$(printf '%s\n' "$content" | _extract_stage3_from_txt | head -n1)"
fi
if [[ -z "$LATEST" ]]; then
  if content="$(curl "${CURL_OPTS[@]}" -m 25 --retry 3 --retry-delay 2 "${BASE_URL}/${TXT_FALLBACK}" 2>/dev/null || true)"; then
    LATEST="$(printf '%s\n' "$content" | _extract_stage3_from_txt | grep -F -- "-${INIT_SYS}-" | head -n1)"
    [[ -n "$LATEST" ]] || LATEST="$(printf '%s\n' "$content" | _extract_stage3_from_txt | head -n1)"
  fi
fi
if [[ -z "$LATEST" ]]; then
  LIST_URL="${BASE_URL}/current-stage3-${G_ARCH}-${INIT_SYS}/"
  if html="$(curl "${CURL_OPTS[@]}" -m 25 --retry 3 --retry-delay 2 "$LIST_URL" 2>/dev/null || true)"; then
    rel="$(printf '%s\n' "$html" | grep -Eo 'href="[^"]*stage3-[^"]+\.tar\.xz"' | sed -E 's/.*href="([^"]+)".*/\1/' | head -n1)"
    if [[ -n "$rel" ]]; then case "$rel" in http*|/*) STAGE_URL="$rel" ;; *) STAGE_URL="${LIST_URL}${rel#./}" ;; esac; fi
  fi
else
  STAGE_URL="${BASE_URL}/${LATEST}"
fi
[[ -n "${STAGE_URL:-}" ]] || err "Cannot find stage3 path."
DIGESTS_URL="${STAGE_URL}.DIGESTS"
cd /mnt/gentoo
wget "${WGET_OPTS[@]}" "$STAGE_URL" "$DIGESTS_URL"
FN="$(basename "$STAGE_URL")"
if HASH=$(awk -v F="$FN" '/^# SHA512 HASH/ {sha=1;next} /^#/ {next} sha && $2==F {print $1; exit}' DIGESTS); then
  echo "${HASH}  ${FN}" | sha512sum -c - || echo "Warning: SHA512 check failed; continuing."
else
  echo "Warning: Could not parse DIGESTS for ${FN}; continuing."
fi
tar xpvf "$FN" --xattrs-include='*.*' --numeric-owner

# ---------- bind mounts ----------
title "Binding /dev, /proc, /sys"
mkdir -p /mnt/gentoo/{proc,sys,dev}
mount -t proc proc /mnt/gentoo/proc
mount --rbind /sys /mnt/gentoo/sys && mount --make-rslave /mnt/gentoo/sys
mount --rbind /dev /mnt/gentoo/dev && mount --make-rslave /mnt/gentoo/dev

# ---------- Portage config ----------
title "Configuring Portage"
CORES="$(nproc || echo 2)"
cat >>/mnt/gentoo/etc/portage/make.conf <<EOF
COMMON_FLAGS="-O2 -pipe -march=native"
CFLAGS="\${COMMON_FLAGS}"
CXXFLAGS="\${COMMON_FLAGS}"
FCFLAGS="\${COMMON_FLAGS}"
FFLAGS="\${COMMON_FLAGS}"
MAKEOPTS="-j${CORES}"
EMERGE_DEFAULT_OPTS="--quiet-build=y"
# Force STABLE branch:
ACCEPT_KEYWORDS="${KW_ARCH}"
EOF

# License policy (global + wildcard)
mkdir -p /mnt/gentoo/etc/portage/package.license
if [[ "$AUTO_LICENSES" =~ ^[Yy]$ ]]; then
  echo 'ACCEPT_LICENSE="*"' >> /mnt/gentoo/etc/portage/make.conf
  echo '*/* *' > /mnt/gentoo/etc/portage/package.license/00-auto
else
  echo 'ACCEPT_LICENSE="@FREE @BINARY-REDISTRIBUTABLE linux-fw-redistributable"' >> /mnt/gentoo/etc/portage/make.conf
  echo '*/* @FREE @BINARY-REDISTRIBUTABLE linux-fw-redistributable' > /mnt/gentoo/etc/portage/package.license/00-auto
fi

# If user asked for insecure web, force Portage/wget/curl to ignore certs too
if [[ "$INSECURE_ALL" =~ ^[Yy]$ ]]; then
  cat >>/mnt/gentoo/etc/portage/make.conf <<'EOF'
# Insecure fetch (user requested)
FETCHCOMMAND="/usr/bin/wget --no-check-certificate -t 5 -T 60 -O \"${DISTDIR}/${FILE}\" \"${URI}\""
RESUMECOMMAND="/usr/bin/wget --no-check-certificate -c -t 5 -T 60 -O \"${DISTDIR}/${FILE}\" \"${URI}\""
# curl alternatives:
#FETCHCOMMAND="/usr/bin/curl -L -k --retry 5 --retry-delay 5 -o \"${DISTDIR}/${FILE}\" \"${URI}\""
#RESUMECOMMAND="/usr/bin/curl -L -k --retry 5 --retry-delay 5 -C - -o \"${DISTDIR}/${FILE}\" \"${URI}\""
EOF
  echo 'check_certificate = off' > /mnt/gentoo/etc/wgetrc
  echo 'insecure'              > /mnt/gentoo/etc/curlrc
fi

# ---------- fstab / crypttab / dracut cfg ----------
title "Writing fstab/crypttab/dracut config"
udevadm settle || true; sleep 1
ROOT_UUID="$(blkid -s UUID -o value "$ROOT_PART")"
BOOT_UUID="$(blkid -s UUID -o value "$BOOT_PART")"
FS_UUID="$(blkid -s UUID -o value /dev/mapper/cryptroot || true)"; [[ -z "$FS_UUID" ]] && { sleep 1; FS_UUID="$(blkid -s UUID -o value /dev/mapper/cryptroot || true)"; }
SWAP_UUID="$(blkid -s UUID -o value "$SWAP_PART" || true)"
if [[ "$BOOTMODE" == "UEFI" ]]; then BOOT_FSTAB="UUID=${BOOT_UUID}  /boot  vfat  defaults,noatime  0 2"; else BOOT_FSTAB="UUID=${BOOT_UUID}  /boot  ext4  defaults,noatime  0 2"; fi
CRYPTTAB_INITRAMFS_LINE="cryptroot UUID=${ROOT_UUID} none luks,discard"
FSTAB_SWAP_LINE=""; CRYPTTAB_LINE=""; RESUME_PARAM=""
if [[ "$SWAP_MODE" == "luks" ]]; then
  CRYPTTAB_LINE="cryptswap UUID=${SWAP_UUID} /root/cryptswap.key luks,discard"
  FSTAB_SWAP_LINE="/dev/mapper/cryptswap none swap sw 0 0"
  [[ "${WANT_HIB,,}" == "yes" ]] && RESUME_PARAM="resume=/dev/mapper/cryptswap"
else
  CRYPTTAB_LINE="cryptswap ${SWAP_PART} /dev/urandom swap,cipher=aes-xts-plain64,size=256,discard"
  FSTAB_SWAP_LINE="/dev/mapper/cryptswap none swap sw 0 0"
fi
ROOT_MNT_OPTS="noatime"; [[ "$ROOT_FS" == "btrfs" ]] && ROOT_MNT_OPTS="${ROOT_MNT_OPTS},compress=zstd:3"
cat >/mnt/gentoo/etc/fstab <<EOF
# /etc/fstab
UUID=${FS_UUID}   /      ${ROOT_FS}  ${ROOT_MNT_OPTS}  0 1
${BOOT_FSTAB}
${FSTAB_SWAP_LINE}
EOF
cat >/mnt/gentoo/etc/crypttab <<EOF
# name  source                 keyfile                 options
${CRYPTTAB_LINE}
EOF
mkdir -p /mnt/gentoo/etc/dracut.conf.d
echo "${CRYPTTAB_INITRAMFS_LINE}" >/mnt/gentoo/etc/crypttab.initramfs
DRACUT_ITEMS='/etc/crypttab.initramfs'; if [[ "$SWAP_MODE" == "luks" && "${WANT_HIB,,}" == "yes" ]]; then DRACUT_ITEMS='/etc/crypttab.initramfs /root/cryptswap.key'; fi
cat >/mnt/gentoo/etc/dracut.conf.d/99-crypt.conf <<EOF
add_dracutmodules+=" crypt "
install_items+="${DRACUT_ITEMS}"
hostonly=yes
EOF
echo "${TIMEZONE}" >/mnt/gentoo/etc/timezone
echo "${LOCALE}"  >>/mnt/gentoo/etc/locale.gen

# ---------- inside-chroot ----------
title "Preparing chroot tasks"
cat >/mnt/gentoo/root/inside-chroot.sh <<'CHROOT'
#!/bin/bash
set -Eeuo pipefail
export PS4='+chroot: ${BASH_SOURCE}:${LINENO}: '
title(){ printf '\n-- %s --\n' "$*"; }

ROOT_PW_FILE=/root/.rootpw
USER_PW_FILE=/root/.userpw
KSEL_FILE=/root/.kernelselect
INIT_SYS_FILE=/root/.initsys
NM_FILE=/root/.nm
MICRO_FILE=/root/.micro
HOST_FILE=/root/.hostname
RESUME_FILE=/root/.resume
BOOTMODE_FILE=/root/.bootmode
PLASMA_FILE=/root/.plasma
SESSION_FILE=/root/.session

title "Sync Portage"
export LANG=C LC_ALL=C
RSYNC_HOST="rsync.gentoo.org"
RSYNC_FAIL=0
if timeout 3 bash -c ":</dev/tcp/${RSYNC_HOST}/873" 2>/dev/null; then
  if ! env PORTAGE_RSYNC_RETRIES=0 PORTAGE_RSYNC_CONNECT_TIMEOUT=5 PORTAGE_RSYNC_INITIAL_TIMEOUT=5 emerge --sync -q; then
    RSYNC_FAIL=1
  fi
else
  RSYNC_FAIL=1
fi
if [[ $RSYNC_FAIL -ne 0 ]]; then
  echo ">> rsync unreachable. Falling back to webrsync (HTTPS snapshot)..."
  mkdir -p /etc/portage/repos.conf
  cat >/etc/portage/repos.conf/gentoo.conf <<'EOF'
[DEFAULT]
main-repo = gentoo
[gentoo]
location = /var/db/repos/gentoo
sync-type = webrsync
sync-uri = https://distfiles.gentoo.org/snapshots/portage
auto-sync = yes
EOF
  emerge-webrsync -q || emaint sync -a
  echo 'PORTAGE_RSYNC_EXTRA_OPTS="--ipv4 --timeout=8"' >> /etc/portage/make.conf
fi

title "Timezone & locale"
emerge --config sys-libs/timezone-data
locale-gen
LOCALE_CHOSEN=$(grep -v '^\s*$' /etc/locale.gen | tail -1 | awk '{print $1}')
eselect locale set "$LOCALE_CHOSEN" || true
env-update && source /etc/profile

title "Hostname"
echo "hostname=\"$(cat "$HOST_FILE")\"" > /etc/conf.d/hostname

title "Profiles"
pick_idx(){ (eselect profile list 2>/dev/null || true) | awk -v pat="$1" -v bad="$2" '$0 ~ pat && (bad=="" || $0 !~ bad){ if (match($0, /\[([0-9]+)\]/, m)) {print m[1]; exit}}'; }
set_profile_if_found(){ local idx="$1" label="$2"; if [[ -n "$idx" ]]; then echo ">> Setting profile: $label (index $idx)"; eselect profile set "$idx" || true; else echo ">> Profile \"$label\" not found. Leaving current profile."; fi; }
init=$(cat "$INIT_SYS_FILE"); plasma=$(cat "$PLASMA_FILE")
if [[ "$init" == "openrc" ]]; then
  if [[ "$plasma" == "yes" ]]; then idx="$(pick_idx "desktop/plasma" "systemd")"; set_profile_if_found "$idx" "desktop/plasma (openrc)"; else idx="$(pick_idx "default/linux/.*/(amd64|arm64)(/|$)" "systemd")"; set_profile_if_found "$idx" "default/linux/* (openrc)"; fi
else
  if [[ "$plasma" == "yes" ]]; then idx="$(pick_idx "desktop/plasma.*systemd" "")"; set_profile_if_found "$idx" "desktop/plasma (systemd)"; else idx="$(pick_idx "systemd" "")"; set_profile_if_found "$idx" "default linux * /systemd"; fi
fi

title "Base tools & firmware"
emerge -q app-admin/sudo app-editors/nano net-misc/dhcpcd sys-kernel/linux-firmware sys-fs/cryptsetup

title "Microcode"
MICRO=$(cat "$MICRO_FILE")
if [[ "$MICRO" == "intel-microcode" ]]; then
  emerge -q sys-firmware/intel-microcode
elif [[ "$MICRO" == "amd-ucode" ]]; then
  emerge -q sys-kernel/amd-ucode
else
  emerge -q "sys-firmware/${MICRO}" || true
fi
# Ensure correct toolchain for kernel build (objtool + BTF)
ensure_kernel_build_stack() {
  # Remove incompatible libelf (ELF Tool Chain) if present
  if portageq has_version / dev-libs/libelf >/dev/null 2>&1; then
    echo "[fix] Removing incompatible dev-libs/libelf"
    emerge -qC dev-libs/libelf || true
  fi
  # Ensure elfutils/pahole and common build deps
  emerge -q --noreplace dev-libs/elfutils dev-util/pahole \
    sys-devel/bc sys-devel/bison sys-devel/flex sys-libs/ncurses app-arch/lz4
}


title "Kernel"
KSEL=$(cat "$KSEL_FILE"); BOOTMODE=$(cat "$BOOTMODE_FILE")
ensure_kernel_build_stack
case "$KSEL" in
  1) emerge -q sys-kernel/gentoo-kernel-bin ;;
   2)
    emerge -q sys-kernel/gentoo-sources sys-apps/pciutils sys-devel/bc sys-libs/ncurses dev-libs/elfutils dev-util/pahole app-arch/lz4
    eselect kernel set 1 || true
    cd /usr/src/linux
    export HOSTCFLAGS="${HOSTCFLAGS:-} -Wno-error=undef -D_LIBELF_INTERNAL_=0"
    make olddefconfig
    make -j"$(nproc)" HOSTCFLAGS="$HOSTCFLAGS"
    make modules_install
    make install
    ;;
   3)
    emerge -q sys-kernel/gentoo-sources sys-kernel/genkernel sys-apps/pciutils sys-devel/bc sys-libs/ncurses dev-libs/elfutils dev-util/pahole app-arch/lz4
    eselect kernel set 1 || true
    # genkernel passes env to its make calls; this quiets objtool + defines the macro
    export HOSTCFLAGS="${HOSTCFLAGS:-} -Wno-error=undef -D_LIBELF_INTERNAL_=0"
    genkernel --install --symlink --menuconfig kernel
    ;;

  *) echo "Unknown kernel option"; exit 1;;
esac

title "Initramfs (Dracut after kernel)"
emerge -q sys-kernel/dracut
KV=$(ls -1 /lib/modules | sort -V | tail -n1)
dracut --kver "$KV" --force

title "Bootloader"
if [[ "$BOOTMODE" == "UEFI" ]]; then emerge -q sys-boot/grub:2 efibootmgr; else emerge -q sys-boot/grub:2; fi
RESUME_ARG=$(cat "$RESUME_FILE")
mkdir -p /etc/default; sed -i 's/^GRUB_CMDLINE_LINUX=.*/# managed below/' /etc/default/grub 2>/dev/null || true

# Configure GRUB kernel cmdline
sed -i 's/^GRUB_CMDLINE_LINUX=.*/# managed below/' /etc/default/grub 2>/dev/null || true
echo "GRUB_CMDLINE_LINUX=\"rd.luks=1 ${RESUME_ARG}\"" >> /etc/default/grub

# Robust GRUB install
if [[ "$BOOTMODE" == "UEFI" ]]; then
  # In UEFI mode we DO NOT pass a disk.
  grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=Gentoo --recheck
else
  # BIOS/MBR mode: pass the whole disk (not a partition)
  _boot_src="$(findmnt -no SOURCE /boot 2>/dev/null || true)"
  _root_src="$(findmnt -no SOURCE / 2>/dev/null || true)"
  _cand=""
  if [[ -n "$_boot_src" ]]; then _cand="$(lsblk -no pkname "$_boot_src" 2>/dev/null || true)"; fi
  if [[ -z "$_cand" && -n "$_root_src" ]]; then _cand="$(lsblk -no pkname "$_root_src" 2>/dev/null || true)"; fi
  if [[ -z "$_cand" && -n "${BOOT_PART:-}" ]]; then _cand="$(lsblk -no pkname "$BOOT_PART" 2>/dev/null || true)"; fi
  if [[ -z "$_cand" && -n "${ROOT_PART:-}" ]]; then _cand="$(lsblk -no pkname "$ROOT_PART" 2>/dev/null || true)"; fi

  if [[ -z "$_cand" ]]; then
    echo "[error] Could not resolve boot disk for grub-install."
    read -rp "Enter BIOS disk (e.g., /dev/sda or /dev/nvme0n1): " _manual
    _cand="${_manual#/dev/}"
  fi

  if [[ -b "/dev/${_cand}" ]]; then
    echo "[grub] Installing to /dev/${_cand} (BIOS)"
    grub-install --target=i386-pc "/dev/${_cand}" --recheck
  else
    echo "[error] Not a block device: /dev/${_cand}"
    exit 1
  fi
fi

grub-mkconfig -o /boot/grub/grub.cfg


title "Network services"
NM=$(cat "$NM_FILE"); INIT=$(cat "$INIT_SYS_FILE")
if [[ "$NM" == "yes" ]]; then
  emerge -q net-misc/networkmanager
  if [[ "$INIT" == "openrc" ]]; then rc-update add dbus default; rc-update add NetworkManager default; else systemctl enable NetworkManager; fi
fi

# Ensure crypt mappings on OpenRC at boot
if [[ "$INIT" == "openrc" ]]; then rc-update add cryptsetup boot; fi

# Desktop (optional)
if [[ "$(cat "$PLASMA_FILE")" == "yes" ]]; then
  SESSION=$(cat "$SESSION_FILE")
  title "Installing KDE Plasma + SDDM ($SESSION)"
  if [[ "$SESSION" == "x11" ]]; then emerge -q x11-base/xorg-server x11-base/xorg-drivers; fi
  emerge -q kde-plasma/plasma-meta x11-misc/sddm kde-apps/konsole kde-apps/dolphin
  if [[ "$INIT" == "openrc" ]]; then
    emerge -q x11-apps/xinit dbus; echo 'DISPLAYMANAGER="sddm"' > /etc/conf.d/xdm
    rc-update add dbus default; rc-update add xdm default
  else
    systemctl enable sddm
  fi
fi

# Passwords & user
echo "root:$(cat "$ROOT_PW_FILE")" | chpasswd
if [[ -f "$USER_PW_FILE" ]]; then
  USERNAME=$(cut -d: -f1 "$USER_PW_FILE"); PASS=$(cut -d: -f2- "$USER_PW_FILE")
  useradd -m -G wheel,video,audio,plugdev,usb,cdrom,portage "$USERNAME"
  echo "$USERNAME:$PASS" | chpasswd
  echo "%wheel ALL=(ALL) ALL" > /etc/sudoers.d/wheel; chmod 440 /etc/sudoers.d/wheel
fi

# LUKS swap key (if used)
if grep -q '^cryptswap ' /etc/crypttab && grep -q 'luks' /etc/crypttab; then
  [[ -f /root/cryptswap.key ]] || { dd if=/dev/urandom of=/root/cryptswap.key bs=4096 count=1 status=none; chmod 0400 /root/cryptswap.key; }
  SWAPPART=$(awk '/^cryptswap / {print $2}' /etc/crypttab)
  if [[ "$SWAPPART" == UUID=* ]]; then U="${SWAPPART#UUID=}"; DEV=$(blkid -U "$U"); else DEV="$SWAPPART"; fi
  cryptsetup luksAddKey "$DEV" /root/cryptswap.key || true
fi

title "Quick world update"
emerge -q --update --newuse --deep @world || true

echo
echo ">>> Chroot configuration complete."
CHROOT
chmod +x /mnt/gentoo/root/inside-chroot.sh

# ---------- pass data into chroot ----------
echo "$ROOT_PW" >/mnt/gentoo/root/.rootpw
[[ -n "${NEWUSER:-}" ]] && echo "${NEWUSER}:${USER_PW}" >/mnt/gentoo/root/.userpw || true
echo "$KSEL"     >/mnt/gentoo/root/.kernelselect
echo "$INIT_SYS" >/mnt/gentoo/root/.initsys
echo "$NM_INSTALL" >/mnt/gentoo/root/.nm
echo "$MICRO"    >/mnt/gentoo/root/.micro
echo "$HOSTNAME" >/mnt/gentoo/root/.hostname
echo "$BOOTMODE" >/mnt/gentoo/root/.bootmode
[[ "${PLASMA,,}" == "yes" ]] && echo "yes" >/mnt/gentoo/root/.plasma || echo "no" >/mnt/gentoo/root/.plasma
echo "$SESSION"  >/mnt/gentoo/root/.session
if [[ "${WANT_HIB,,}" == "yes" && "$SWAP_MODE" == "luks" ]]; then echo "resume=/dev/mapper/cryptswap" >/mnt/gentoo/root/.resume; else echo "" >/mnt/gentoo/root/.resume; fi

# ---------- chroot in ----------
title "Entering chroot"
cp -L /etc/resolv.conf /mnt/gentoo/etc/
if ! chroot /mnt/gentoo /bin/bash -c "/root/inside-chroot.sh"; then
  echo "WARN: inside-chroot failed (see output above). You can chroot manually:"
  echo "      chroot /mnt/gentoo /bin/bash"
  exit 1
fi

# ---------- cleanup ----------
title "Cleanup"
rm -f /mnt/gentoo/root/.rootpw /mnt/gentoo/root/.userpw /mnt/gentoo/root/.kernelselect \
      /mnt/gentoo/root/.initsys /mnt/gentoo/root/.nm /mnt/gentoo/root/.micro \
      /mnt/gentoo/root/.hostname /mnt/gentoo/root/.resume /mnt/gentoo/root/.bootmode \
      /mnt/gentoo/root/.plasma /mnt/gentoo/root/.session || true

title "All done!"
echo "Now:"
echo "  umount -R /mnt/gentoo"
echo "  swapoff -a || true"
echo "  cryptsetup close cryptswap 2>/dev/null || true"
echo "  cryptsetup close cryptroot"
echo "  reboot"
