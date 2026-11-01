#!/usr/bin/env bash
# HANYA UNTUK UJI LOKAL. Membuat CA sementara dan sertifikat Monitor (SAN IP 172.16.202.22).
# CA lab resmi diterbitkan integrator. Private key CA tidak boleh tinggal di VM Source/Monitor:
# setelah dipakai, pindahkan atau hapus ca.key dari folder keluaran.
# Pakai:  bash deployment/monitor/make-test-tls.sh /folder/kosong [IP_SAN]
set -euo pipefail

OUT="${1:?pakai: make-test-tls.sh FOLDER_KOSONG [IP_SAN]}"
SAN_IP="${2:-172.16.202.22}"

mkdir -p "$OUT"
if [ -n "$(ls -A "$OUT")" ]; then
    echo "GAGAL: folder $OUT tidak kosong; tidak menimpa berkas yang ada." >&2
    exit 1
fi
umask 077
ext="$(mktemp)"
trap 'rm -f "$ext"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca.key"
openssl req -x509 -new -key "$OUT/ca.key" -sha256 -days 30 -subj "/CN=LogLab TEST CA (uji lokal)" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$OUT/ca.crt"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/tls.key"
openssl req -new -key "$OUT/tls.key" -subj "/CN=loglab-monitor" -out "$OUT/tls.csr"
printf 'subjectAltName=IP:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$SAN_IP" > "$ext"
openssl x509 -req -in "$OUT/tls.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial -days 30 -sha256 \
    -extfile "$ext" -out "$OUT/tls.crt" 2>/dev/null
rm -f "$OUT/tls.csr" "$OUT/ca.srl"
openssl verify -CAfile "$OUT/ca.crt" "$OUT/tls.crt" >/dev/null
echo "OK: ca.crt tls.crt tls.key dibuat di $OUT (berlaku 30 hari, SAN IP $SAN_IP)."
echo "INGAT: pindahkan atau hapus $OUT/ca.key; jangan biarkan tersimpan di VM."
