#!/usr/bin/env bash
set -euo pipefail

umask 077

DATADIR="${BTX_WALLET_BACKUP_DATADIR:-}"
WALLET="${BTX_WALLET_BACKUP_WALLET:-miner}"
BACKUP_DIR="${BTX_WALLET_BACKUP_DIR:-}"
CLI="${BTX_WALLET_BACKUP_CLI:-btx-cli}"
FORMAT="${BTX_WALLET_BACKUP_FORMAT:-bundle}"

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
    --format=*)
      FORMAT="${arg#*=}"
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
bundle_dir="${base}.bundle"
bundle_result="${base}.bundle.json"
wallet_backup="${base}.sqlite.bak"
descriptors_backup="${base}.descriptors.json"
walletinfo_backup="${base}.walletinfo.json"
integrity_backup="${base}.integrity.json"
balances_backup="${base}.balances.json"
shielded_balance_backup="${base}.shielded-balance.json"
shielded_addresses_backup="${base}.shielded-addresses.json"
checksum_file="${base}.sha256"

wallet_cli() {
  if [[ -n "${DATADIR}" ]]; then
    "${CLI}" "-datadir=${DATADIR}" "-rpcwallet=${WALLET}" "$@"
  else
    "${CLI}" "-rpcwallet=${WALLET}" "$@"
  fi
}

if [[ "${FORMAT}" != "legacy" ]]; then
  if wallet_cli help backupwalletbundle >/dev/null 2>&1; then
    wallet_cli backupwalletbundle "${bundle_dir}" > "${bundle_result}"
    chmod -R go-rwx "${bundle_dir}"
    chmod 600 "${bundle_result}"
    printf 'bundle_dir=%s\n' "${bundle_dir}"
    printf 'bundle_result=%s\n' "${bundle_result}"
    exit 0
  fi

  if [[ "${FORMAT}" == "bundle" ]]; then
    echo "backupwalletbundle RPC is unavailable; rerun with --format=legacy to use raw backupwallet fallback" >&2
    exit 1
  fi
fi

if wallet_cli help z_verifywalletintegrity >/dev/null 2>&1; then
  wallet_cli z_verifywalletintegrity > "${integrity_backup}"
fi
if wallet_cli help getbalances >/dev/null 2>&1; then
  wallet_cli getbalances > "${balances_backup}"
fi
if wallet_cli help z_gettotalbalance >/dev/null 2>&1; then
  wallet_cli z_gettotalbalance > "${shielded_balance_backup}"
fi
if wallet_cli help z_listaddresses >/dev/null 2>&1; then
  wallet_cli z_listaddresses > "${shielded_addresses_backup}"
fi

wallet_cli backupwallet "${wallet_backup}"

if [[ ! -s "${wallet_backup}" ]]; then
  echo "Wallet backup file was not created: ${wallet_backup}" >&2
  exit 1
fi

wallet_cli listdescriptors true > "${descriptors_backup}"
wallet_cli getwalletinfo > "${walletinfo_backup}"
shasum -a 256 "${wallet_backup}" > "${checksum_file}"

chmod 600 "${wallet_backup}" "${descriptors_backup}" "${walletinfo_backup}" "${checksum_file}"
for optional_file in "${integrity_backup}" "${balances_backup}" "${shielded_balance_backup}" "${shielded_addresses_backup}"; do
  if [[ -e "${optional_file}" ]]; then
    chmod 600 "${optional_file}"
  fi
done

printf 'wallet_backup=%s\n' "${wallet_backup}"
printf 'descriptors_backup=%s\n' "${descriptors_backup}"
printf 'walletinfo_backup=%s\n' "${walletinfo_backup}"
if [[ -e "${integrity_backup}" ]]; then
  printf 'integrity_backup=%s\n' "${integrity_backup}"
fi
if [[ -e "${balances_backup}" ]]; then
  printf 'balances_backup=%s\n' "${balances_backup}"
fi
if [[ -e "${shielded_balance_backup}" ]]; then
  printf 'shielded_balance_backup=%s\n' "${shielded_balance_backup}"
fi
if [[ -e "${shielded_addresses_backup}" ]]; then
  printf 'shielded_addresses_backup=%s\n' "${shielded_addresses_backup}"
fi
printf 'checksum=%s\n' "${checksum_file}"
