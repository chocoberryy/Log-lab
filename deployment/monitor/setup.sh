#!/usr/bin/env bash
# Pasang peran Monitor di guest Debian 13 (VM B, hostname loglab-monitor). Aman dipanggil ulang:
# env, secret, sertifikat, dan data yang sudah ada tidak ditimpa.
#
# Pakai (dari ~/LogLab, sebagai user loglab):   sudo bash deployment/monitor/setup.sh
# Opsi lingkungan:
#   LOGLAB_SKIP_FIREWALL=1   lewati pemasangan firewall (mis. saat masih SSH lewat NAT)
set -euo pipefail

SERVICE_USER="loglab-svc"
LAB_USER="loglab"
WANTED_HOSTNAME="loglab-monitor"
MONITOR_IP="172.16.202.22"
MONITOR_PORT="8443"
CONF_DIR="/etc/loglab"
DATA_DIR="/var/lib/loglab"
BACKUP_DIR="/var/backups/loglab"
ENV_FILE="${CONF_DIR}/monitor.env"
UNIT_DIR="/etc/systemd/system"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${HERE}/../.." && pwd)"
PYTHON="${PROJECT_DIR}/.venv/bin/python"

say()  { printf '==> %s\n' "$*"; }
fail() { printf 'GAGAL: %s\n' "$*" >&2; exit 1; }

check_root() {
    [ "$(id -u)" -eq 0 ] || fail "jalankan dengan sudo: sudo bash deployment/monitor/setup.sh"
}

check_os() {
    say "Memeriksa OS dan Python"
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${ID:-}" = "debian" ] && [ "${VERSION_ID:-}" = "13" ] || fail "OS harus Debian 13 (ditemukan: ${PRETTY_NAME:-tidak diketahui})"
    [ -x "$PYTHON" ] || fail "virtualenv belum ada. Jalankan dulu sebagai user ${LAB_USER}: make dev-setup"
    "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 13) else 1)' || fail "Python virtualenv harus 3.13"
    "$PYTHON" -c 'import loglab' || fail "package loglab belum terpasang di virtualenv (jalankan make dev-setup)"
}

install_packages() {
    say "Memasang paket sistem yang dibutuhkan"
    local missing=() package
    for package in nftables acl curl openssl ca-certificates; do
        dpkg -s "$package" >/dev/null 2>&1 || missing+=("$package")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
    fi
}

set_hostname() {
    [ "$(hostname)" = "$WANTED_HOSTNAME" ] && return 0
    say "Mengatur hostname menjadi ${WANTED_HOSTNAME}"
    hostnamectl set-hostname "$WANTED_HOSTNAME"
    if grep -q '^127\.0\.1\.1' /etc/hosts; then
        sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t${WANTED_HOSTNAME}/" /etc/hosts
    else
        printf '127.0.1.1\t%s\n' "$WANTED_HOSTNAME" >> /etc/hosts
    fi
}

ensure_service_user_and_dirs() {
    say "Menyiapkan user ${SERVICE_USER} dan folder (izin sesuai kontrak)"
    if ! getent passwd "$SERVICE_USER" >/dev/null; then
        adduser --system --group --no-create-home --home "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    install -d -o root -g "$SERVICE_USER" -m 0750 "$CONF_DIR"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$DATA_DIR" "$BACKUP_DIR"
}

grant_project_access() {
    say "Memberi ${SERVICE_USER} akses baca source/virtualenv (tanpa membuka .ssh)"
    local home
    home="$(getent passwd "$LAB_USER" | cut -d: -f6)"
    [ "$PROJECT_DIR" = "${home}/LogLab" ] || fail "repo harus berada di ${home}/LogLab sesuai kontrak (sekarang: ${PROJECT_DIR})"
    setfacl -m "u:${SERVICE_USER}:x" "$home"
    setfacl -m "u:${SERVICE_USER}:rx" "$PROJECT_DIR"
    setfacl -R -m "u:${SERVICE_USER}:rX" "${PROJECT_DIR}/src" "${PROJECT_DIR}/.venv" "${PROJECT_DIR}/config"
    runuser -u "$SERVICE_USER" -- "$PYTHON" -c 'import loglab.monitor_main' || fail "${SERVICE_USER} tidak dapat memuat aplikasi"
    if runuser -u "$SERVICE_USER" -- ls "${home}/.ssh" >/dev/null 2>&1; then
        fail "${SERVICE_USER} dapat membaca ${home}/.ssh; perbaiki izin sebelum melanjutkan"
    fi
}

ensure_env() {
    if [ -e "$ENV_FILE" ]; then
        say "Env sudah ada, tidak ditimpa: ${ENV_FILE}"
    else
        say "Membuat ${ENV_FILE} dari template (berisi placeholder)"
        install -m 0600 -o root -g root "${PROJECT_DIR}/config/monitor.example.env" "$ENV_FILE"
    fi
    chown root:root "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
}

validate_env() {
    say "Memvalidasi env terhadap kontrak (nilai tidak ditampilkan)"
    if ! "$PYTHON" "${PROJECT_DIR}/scripts/check_contract.py" --role monitor --env "$ENV_FILE"; then
        cat >&2 <<MSG

Env belum valid. Isi dua nilai rahasia di ${ENV_FILE}, lalu jalankan setup lagi:
  LOGLAB_SOURCE_TOKEN          : 64 huruf hex, SAMA persis dengan milik Source (sepakati dengan Erna)
                                 contoh membuat:  openssl rand -hex 32
  LOGLAB_OPERATOR_PASSWORD_HASH: hash password operator, buat dengan:
                                 ${PYTHON} -c "from getpass import getpass; from loglab.security import hash_password; print(hash_password(getpass()))"
  (password minimal 12 karakter; simpan password aslinya di tempat privat, jangan di Git)
MSG
        exit 1
    fi
}

check_tls() {
    say "Memeriksa sertifikat TLS"
    local file
    for file in ca.crt tls.crt tls.key; do
        [ -s "${CONF_DIR}/${file}" ] || fail "${CONF_DIR}/${file} belum ada. Minta CA/sertifikat lab dari integrator (SAN harus IP ${MONITOR_IP}). Hanya untuk uji lokal: bash deployment/monitor/make-test-tls.sh /folder/kosong"
    done
    chown root:"$SERVICE_USER" "${CONF_DIR}/tls.key" "${CONF_DIR}/tls.crt" "${CONF_DIR}/ca.crt"
    chmod 0640 "${CONF_DIR}/tls.key"
    chmod 0644 "${CONF_DIR}/tls.crt" "${CONF_DIR}/ca.crt"
    openssl verify -CAfile "${CONF_DIR}/ca.crt" "${CONF_DIR}/tls.crt" >/dev/null || fail "tls.crt tidak diterbitkan oleh ca.crt"
    openssl x509 -in "${CONF_DIR}/tls.crt" -noout -ext subjectAltName | grep -q "IP Address:${MONITOR_IP}" \
        || fail "SAN sertifikat tidak memuat IP ${MONITOR_IP}"
    runuser -u "$SERVICE_USER" -- test -r "${CONF_DIR}/tls.key" || fail "${SERVICE_USER} tidak bisa membaca tls.key"
    if [ -e "${CONF_DIR}/ca.key" ]; then
        printf 'PERINGATAN: %s/ca.key ada di VM ini. Kontrak melarang private key CA di VM; pindahkan ke tempat privat.\n' "$CONF_DIR" >&2
    fi
}

install_units() {
    say "Memasang service systemd dan timer backup"
    local unit
    for unit in loglab-monitor.service loglab-monitor-backup.service loglab-monitor-backup.timer; do
        install -m 0644 -o root -g root "${HERE}/${unit}" "${UNIT_DIR}/${unit}"
    done
    systemctl daemon-reload
}

install_firewall() {
    if [ "${LOGLAB_SKIP_FIREWALL:-0}" = "1" ]; then
        say "Firewall dilewati (LOGLAB_SKIP_FIREWALL=1)"
        return 0
    fi
    say "Memasang firewall (default-deny; hanya host dan Source)"
    nft -c -f "${HERE}/monitor.nft" || fail "sintaks monitor.nft ditolak nft; firewall lama tidak diubah"
    if [ -e /etc/nftables.conf ] && [ ! -e /etc/nftables.conf.pre-loglab ]; then
        cp -p /etc/nftables.conf /etc/nftables.conf.pre-loglab
    fi
    install -m 0644 -o root -g root "${HERE}/monitor.nft" /etc/nftables.conf
    systemctl enable nftables >/dev/null
    systemctl restart nftables
    printf 'CATATAN: SSH baru hanya diterima dari 172.16.202.1. Sesi yang sedang terbuka tetap hidup; console VMware selalu bisa dipakai untuk pemulihan.\n'
}

has_monitor_ip() {
    ip -4 -o addr show | grep -q " ${MONITOR_IP}/"
}

start_service() {
    systemctl enable loglab-monitor.service >/dev/null
    systemctl enable --now loglab-monitor-backup.timer >/dev/null
    if ! has_monitor_ip; then
        printf 'BELUM SIAP: IP %s belum terpasang di VM ini. Atur adapter host-only (IP statis), lalu jalankan setup lagi.\n' "$MONITOR_IP" >&2
        exit 3
    fi
    say "Menjalankan loglab-monitor.service"
    systemctl restart loglab-monitor.service
}

health_check() {
    say "Menunggu /health lewat HTTPS dengan CA lab"

    for _ in $(seq 1 30); do
        if curl -fsS --cacert "${CONF_DIR}/ca.crt" "https://${MONITOR_IP}:${MONITOR_PORT}/health" 2>/dev/null | grep -q '"state":"ready"'; then
            say "SIAP: Monitor menjawab health. Ini baru bukti proses hidup, bukan bukti delivery."
            return 0
        fi
        sleep 1
    done
    systemctl --no-pager --lines=15 status loglab-monitor.service >&2 || true
    fail "health check gagal setelah 30 detik; lihat: journalctl -u loglab-monitor.service -n 50"
}

main() {
    check_root
    check_os
    install_packages
    set_hostname
    ensure_service_user_and_dirs
    grant_project_access
    ensure_env
    validate_env
    check_tls
    install_units
    install_firewall
    start_service
    health_check
}

main "$@"
