#ifndef BITCOINPQC_WRAPPER_H
#define BITCOINPQC_WRAPPER_H

#include <napi.h>
#include <libbitcoinpqc/bitcoinpqc.h>

// Key size functions
Napi::Value GetPublicKeySize(const Napi::CallbackInfo& info);
Napi::Value GetSecretKeySize(const Napi::CallbackInfo& info);
Napi::Value GetSignatureSize(const Napi::CallbackInfo& info);

// Key generation, signing and verification
Napi::Value GenerateKeypair(const Napi::CallbackInfo& info);
Napi::Value SignMessage(const Napi::CallbackInfo& info);
Napi::Value VerifySignature(const Napi::CallbackInfo& info);

#endif
