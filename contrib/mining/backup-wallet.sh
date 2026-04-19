#!/usr/bin/env bash
set -euo pipefail

umask 077

DATADIR="${BTX_WALLET_BACKUP_DATADIR:-}"
WALLET="${BTX_WALLET_BACKUP_WALLET:-miner}"
BACKUP_DIR="${BTX_WALLET_BACKUP_DIR:-}"
CLI="${BTX_WALLET_BACKUP_CLI:-btx-cli}"

for arg in "$@"; do
  case "${arg}" in
    --datadir=*)
      DATADIR="${arg#*=}"
      ;;
    --wallet=*)
      WALLET="${arg#*=}"
      ;;
    --backup-dir=*)
      BACKUP_DIR="${arg#*=}"
      ;;
    --cli=*)
      CLI="${arg#*=}"
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${BACKUP_DIR}" ]]; then
  if [[ -n "${DATADIR}" ]]; then
    BACKUP_DIR="${DATADIR}/backups"
  else
    BACKUP_DIR="${PWD}/wallet-backups"
  fi
fi

mkdir -p "${BACKUP_DIR}"

timestamp="$(date +%Y%m%d-%H%M%S)"
base="${BACKUP_DIR}/${WALLET}-${timestamp}"
wallet_backup="${base}.sqlite.bak"
descriptors_backup="${base}.descriptors.json"
walletinfo_backup="${base}.walletinfo.json"
checksum_file="${base}.sha256"

wallet_cli() {
  if [[ -n "${DATADIR}" ]]; then
    "${CLI}" "-datadir=${DATADIR}" "-rpcwallet=${WALLET}" "$@"
  else
    "${CLI}" "-rpcwallet=${WALLET}" "$@"
  fi
}

wallet_cli backupwallet "${wallet_backup}"

if [[ ! -s "${wallet_backup}" ]]; then
  echo "Wallet backup file was not created: ${wallet_backup}" >&2
  exit 1
fi

wallet_cli listdescriptors true > "${descriptors_backup}"
wallet_cli getwalletinfo > "${walletinfo_backup}"
shasum -a 256 "${wallet_backup}" > "${checksum_file}"

chmod 600 "${wallet_backup}" "${descriptors_backup}" "${walletinfo_backup}" "${checksum_file}"

printf 'wallet_backup=%s\n' "${wallet_backup}"
printf 'descriptors_backup=%s\n' "${descriptors_backup}"
printf 'walletinfo_backup=%s\n' "${walletinfo_backup}"
printf 'checksum=%s\n' "${checksum_file}"
