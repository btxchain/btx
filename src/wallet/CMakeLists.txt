# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by bitcoind and bitcoin-wallet executables.
add_library(bitcoin_wallet STATIC EXCLUDE_FROM_ALL
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  migrate.cpp
  pq_keyderivation.cpp
  receive.cpp
  rpc/addresses.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/encrypt.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/sweep.cpp
  bridge_wallet.cpp
  shielded_fees.cpp
  shielded_rpc.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/wallet.cpp
  scriptpubkeyman.cpp
  shielded_coins.cpp
  shielded_privacy.cpp
  shielded_wallet.cpp
  spend.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  walletutil.cpp
)
target_link_libraries(bitcoin_wallet
  PUBLIC
    bitcoin_common
  PRIVATE
    core_interface
    bitcoin_shielded
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)

if(NOT USE_SQLITE AND NOT USE_BDB)
  message(FATAL_ERROR "Wallet functionality requested but no BDB or SQLite support available.")
endif()
if(USE_SQLITE)
  target_sources(bitcoin_wallet PRIVATE sqlite.cpp)
  # Prefer the modern imported target name when CMake provides it, while
  # keeping compatibility with older and unofficial SQLite package layouts.
  if(TARGET unofficial::sqlite3::sqlite3)
    set(sqlite_wallet_target unofficial::sqlite3::sqlite3)
  elseif(TARGET SQLite3::SQLite3)
    set(sqlite_wallet_target SQLite3::SQLite3)
  else()
    set(sqlite_wallet_target SQLite::SQLite3)
  endif()
  target_link_libraries(bitcoin_wallet
    PRIVATE
      ${sqlite_wallet_target}
  )
endif()
if(USE_BDB)
  target_sources(bitcoin_wallet PRIVATE bdb.cpp salvage.cpp)
  target_link_libraries(bitcoin_wallet PUBLIC BerkeleyDB::BerkeleyDB)
endif()
