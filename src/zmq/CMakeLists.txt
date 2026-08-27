# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_zmq STATIC EXCLUDE_FROM_ALL
  zmqabstractnotifier.cpp
  zmqnotificationinterface.cpp
  zmqpublishnotifier.cpp
  zmqrpc.cpp
  zmqutil.cpp
)
target_compile_definitions(bitcoin_zmq
  INTERFACE
    ENABLE_ZMQ=1
)
target_link_libraries(bitcoin_zmq
  PRIVATE
    core_interface
    univalue
    zeromq
    Boost::headers
)
# Linux gcc-13 + libzmq.so + libnorm.so.1: do not add -lstdc++ / PUBLIC stdc++
# here. That looks like the C++ runtime and gets stripped; it also resolves
# to gcc-13's libstdc++.so which lacks __cxa_call_terminate@CXXABI_1.3.15.
# The actual lever is -Wl,--unresolved-symbols=ignore-in-shared-libs on the
# linux archive-group executables in src/CMakeLists.txt.
