{
  "targets": [
    {
      "target_name": "bitcoinpqc",
      "sources": [
        "src/native/bitcoinpqc_addon.cc",
        "src/c_sources/bitcoinpqc.c",
        "src/c_sources/ml_dsa/keygen.c",
        "src/c_sources/ml_dsa/sign.c",
        "src/c_sources/ml_dsa/verify.c",
        "src/c_sources/ml_dsa/utils.c",
        "src/c_sources/slh_dsa/keygen.c",
        "src/c_sources/slh_dsa/sign.c",
        "src/c_sources/slh_dsa/verify.c",
        "src/c_sources/slh_dsa/utils.c",
        "src/c_sources/dilithium_ref/sign.c",
        "src/c_sources/dilithium_ref/packing.c",
        "src/c_sources/dilithium_ref/polyvec.c",
        "src/c_sources/dilithium_ref/poly.c",
        "src/c_sources/dilithium_ref/ntt.c",
        "src/c_sources/dilithium_ref/reduce.c",
        "src/c_sources/dilithium_ref/rounding.c",
        "src/c_sources/dilithium_ref/fips202.c",
        "src/c_sources/dilithium_ref/symmetric-shake.c",
        "src/c_sources/dilithium_ref/randombytes_custom.c",
        "src/c_sources/sphincsplus_ref/address.c",
        "src/c_sources/sphincsplus_ref/fors.c",
        "src/c_sources/sphincsplus_ref/hash_shake.c",
        "src/c_sources/sphincsplus_ref/merkle.c",
        "src/c_sources/sphincsplus_ref/sign.c",
        "src/c_sources/sphincsplus_ref/thash_shake_simple.c",
        "src/c_sources/sphincsplus_ref/utils.c",
        "src/c_sources/sphincsplus_ref/utilsx1.c",
        "src/c_sources/sphincsplus_ref/wots.c",
        "src/c_sources/sphincsplus_ref/wotsx1.c",
        "src/c_sources/sphincsplus_ref/fips202.c"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src/c_sources/include",
        "src/c_sources/dilithium_ref",
        "src/c_sources/sphincsplus_ref"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "cflags": [ "-Wno-sign-compare", "-Wno-unused-variable", "-Wno-implicit-function-declaration" ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "DILITHIUM_MODE=2",
        "CRYPTO_ALGNAME=\"SPHINCS+-shake-128s\"",
        "PARAMS=sphincs-shake-128s",
        "CUSTOM_RANDOMBYTES=1"
      ],
      "conditions": [
        ["OS=='win'", {
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1
            }
          }
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
            "OTHER_CFLAGS": [
              "-Wno-sign-compare",
              "-Wno-unused-variable",
              "-Wno-implicit-function-declaration"
            ]
          },
        }]
      ]
    }
  ]
}
