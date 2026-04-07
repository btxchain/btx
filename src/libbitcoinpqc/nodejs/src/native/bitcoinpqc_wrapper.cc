#include "bitcoinpqc_wrapper.h"

Napi::Value GetPublicKeySize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  size_t size = bitcoin_pqc_public_key_size(static_cast<bitcoin_pqc_algorithm_t>(algorithm));

  return Napi::Number::New(env, static_cast<double>(size));
}

Napi::Value GetSecretKeySize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  size_t size = bitcoin_pqc_secret_key_size(static_cast<bitcoin_pqc_algorithm_t>(algorithm));

  return Napi::Number::New(env, static_cast<double>(size));
}

Napi::Value GetSignatureSize(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  size_t size = bitcoin_pqc_signature_size(static_cast<bitcoin_pqc_algorithm_t>(algorithm));

  return Napi::Number::New(env, static_cast<double>(size));
}

Napi::Value GenerateKeypair(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsTypedArray()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  Napi::Uint8Array randomData = info[1].As<Napi::Uint8Array>();

  if (randomData.ByteLength() < 128) {
    Napi::Error::New(env, "Random data must be at least 128 bytes").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Set up keypair struct
  bitcoin_pqc_keypair_t keypair;
  bitcoin_pqc_error_t result = bitcoin_pqc_keygen(
    static_cast<bitcoin_pqc_algorithm_t>(algorithm),
    &keypair,
    randomData.Data(),
    randomData.ByteLength()
  );

  // Check for errors
  if (result != BITCOIN_PQC_OK) {
    Napi::Error::New(env, "Key generation failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Create result object
  Napi::Object returnValue = Napi::Object::New(env);

  // Copy public key
  Napi::Uint8Array publicKey = Napi::Uint8Array::New(env, keypair.public_key_size);
  memcpy(publicKey.Data(), keypair.public_key, keypair.public_key_size);
  returnValue.Set("publicKey", publicKey);

  // Copy secret key
  Napi::Uint8Array secretKey = Napi::Uint8Array::New(env, keypair.secret_key_size);
  memcpy(secretKey.Data(), keypair.secret_key, keypair.secret_key_size);
  returnValue.Set("secretKey", secretKey);

  // Set result code
  returnValue.Set("resultCode", Napi::Number::New(env, static_cast<double>(result)));

  // Clean up
  bitcoin_pqc_keypair_free(&keypair);

  return returnValue;
}

Napi::Value SignMessage(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsTypedArray() || !info[2].IsTypedArray()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  Napi::Uint8Array secretKey = info[1].As<Napi::Uint8Array>();
  Napi::Uint8Array message = info[2].As<Napi::Uint8Array>();

  // Set up signature struct
  bitcoin_pqc_signature_t signature;
  bitcoin_pqc_error_t result = bitcoin_pqc_sign(
    static_cast<bitcoin_pqc_algorithm_t>(algorithm),
    secretKey.Data(),
    secretKey.ByteLength(),
    message.Data(),
    message.ByteLength(),
    &signature
  );

  // Check for errors
  if (result != BITCOIN_PQC_OK) {
    Napi::Error::New(env, "Signing failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Create result object
  Napi::Object returnValue = Napi::Object::New(env);

  // Copy signature
  Napi::Uint8Array signatureData = Napi::Uint8Array::New(env, signature.signature_size);
  memcpy(signatureData.Data(), signature.signature, signature.signature_size);
  returnValue.Set("signature", signatureData);

  // Set result code
  returnValue.Set("resultCode", Napi::Number::New(env, static_cast<double>(result)));

  // Clean up
  bitcoin_pqc_signature_free(&signature);

  return returnValue;
}

Napi::Value VerifySignature(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 4 || !info[0].IsNumber() || !info[1].IsTypedArray() ||
      !info[2].IsTypedArray() || !info[3].IsTypedArray()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  Napi::Uint8Array publicKey = info[1].As<Napi::Uint8Array>();
  Napi::Uint8Array message = info[2].As<Napi::Uint8Array>();
  Napi::Uint8Array signature = info[3].As<Napi::Uint8Array>();

  // Verify signature
  bitcoin_pqc_error_t result = bitcoin_pqc_verify(
    static_cast<bitcoin_pqc_algorithm_t>(algorithm),
    publicKey.Data(),
    publicKey.ByteLength(),
    message.Data(),
    message.ByteLength(),
    signature.Data(),
    signature.ByteLength()
  );

  // Return result code
  return Napi::Number::New(env, static_cast<double>(result));
}
