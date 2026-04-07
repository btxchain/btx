#include <cstring>
#include <napi.h>

// Mock key sizes
const int SECP256K1_PK_SIZE = 32;
const int SECP256K1_SK_SIZE = 32;
const int SECP256K1_SIG_SIZE = 64;

const int ML_DSA_44_PK_SIZE = 1312;
const int ML_DSA_44_SK_SIZE = 2528;
const int ML_DSA_44_SIG_SIZE = 2420;

const int SLH_DSA_SHAKE_128S_PK_SIZE = 32;
const int SLH_DSA_SHAKE_128S_SK_SIZE = 64;
const int SLH_DSA_SHAKE_128S_SIG_SIZE = 7856;

// Error codes
const int OK = 0;
const int BAD_ARGUMENT = -1;
const int BAD_KEY = -2;
const int BAD_SIGNATURE = -3;
const int NOT_IMPLEMENTED = -4;

Napi::Value GetPublicKeySize(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();

  int size = 0;
  switch (algorithm) {
  case 0:
    size = SECP256K1_PK_SIZE;
    break;
  case 1:
    size = ML_DSA_44_PK_SIZE;
    break;
  case 2:
    size = SLH_DSA_SHAKE_128S_PK_SIZE;
    break;
  default:
    size = 0;
  }

  return Napi::Number::New(env, size);
}

Napi::Value GetSecretKeySize(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();

  int size = 0;
  switch (algorithm) {
  case 0:
    size = SECP256K1_SK_SIZE;
    break;
  case 1:
    size = ML_DSA_44_SK_SIZE;
    break;
  case 2:
    size = SLH_DSA_SHAKE_128S_SK_SIZE;
    break;
  default:
    size = 0;
  }

  return Napi::Number::New(env, size);
}

Napi::Value GetSignatureSize(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();

  int size = 0;
  switch (algorithm) {
  case 0:
    size = SECP256K1_SIG_SIZE;
    break;
  case 1:
    size = ML_DSA_44_SIG_SIZE;
    break;
  case 2:
    size = SLH_DSA_SHAKE_128S_SIG_SIZE;
    break;
  default:
    size = 0;
  }

  return Napi::Number::New(env, size);
}

Napi::Value GenerateKeypair(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsTypedArray()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  Napi::Uint8Array randomData = info[1].As<Napi::Uint8Array>();

  if (randomData.ByteLength() < 128) {
    Napi::Error::New(env, "Random data must be at least 128 bytes")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  if (algorithm < 0 || algorithm > 3) {
    Napi::Error::New(env, "Invalid algorithm").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get key sizes
  int pkSize = 0;
  int skSize = 0;

  switch (algorithm) {
  case 0:
    pkSize = SECP256K1_PK_SIZE;
    skSize = SECP256K1_SK_SIZE;
    break;
  case 1:
    pkSize = ML_DSA_44_PK_SIZE;
    skSize = ML_DSA_44_SK_SIZE;
    break;
  case 2:
    pkSize = SLH_DSA_SHAKE_128S_PK_SIZE;
    skSize = SLH_DSA_SHAKE_128S_SK_SIZE;
    break;
  default:
    return Napi::Number::New(env, BAD_ARGUMENT);
  }

  // Create result object
  Napi::Object result = Napi::Object::New(env);

  // Create dummy keys
  Napi::Uint8Array publicKey = Napi::Uint8Array::New(env, pkSize);
  Napi::Uint8Array secretKey = Napi::Uint8Array::New(env, skSize);

  // Use random data to fill the keys
  for (size_t i = 0; i < pkSize && i < randomData.ByteLength(); i++) {
    publicKey[i] = randomData[i];
  }

  for (size_t i = 0; i < skSize && i < randomData.ByteLength(); i++) {
    secretKey[i] = randomData[i + randomData.ByteLength() / 2];
  }

  result.Set("publicKey", publicKey);
  result.Set("secretKey", secretKey);
  result.Set("resultCode", OK);

  return result;
}

Napi::Value SignMessage(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsTypedArray() ||
      !info[2].IsTypedArray()) {
    Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
    return env.Null();
  }

  int algorithm = info[0].As<Napi::Number>().Int32Value();
  Napi::Uint8Array secretKey = info[1].As<Napi::Uint8Array>();
  Napi::Uint8Array message = info[2].As<Napi::Uint8Array>();

  if (algorithm < 0 || algorithm > 3) {
    Napi::Error::New(env, "Invalid algorithm").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get expected signature size
  int sigSize = 0;
  int expectedSkSize = 0;

  switch (algorithm) {
  case 0:
    sigSize = SECP256K1_SIG_SIZE;
    expectedSkSize = SECP256K1_SK_SIZE;
    break;
  case 1:
    sigSize = ML_DSA_44_SIG_SIZE;
    expectedSkSize = ML_DSA_44_SK_SIZE;
    break;
  case 2:
    sigSize = SLH_DSA_SHAKE_128S_SIG_SIZE;
    expectedSkSize = SLH_DSA_SHAKE_128S_SK_SIZE;
    break;
  default:
    return Napi::Number::New(env, BAD_ARGUMENT);
  }

  // Check key size
  if (secretKey.ByteLength() != expectedSkSize) {
    Napi::Object result = Napi::Object::New(env);
    result.Set("signature", Napi::Uint8Array::New(env, 0));
    result.Set("resultCode", BAD_KEY);
    return result;
  }

  // Create result object
  Napi::Object result = Napi::Object::New(env);

  // Create dummy signature
  Napi::Uint8Array signature = Napi::Uint8Array::New(env, sigSize);

  // Use message to fill the signature (in a real implementation this would be a
  // proper signature)
  for (size_t i = 0; i < sigSize; i++) {
    signature[i] = i < message.ByteLength() ? message[i] : 0;
  }

  result.Set("signature", signature);
  result.Set("resultCode", OK);

  return result;
}

Napi::Value VerifySignature(const Napi::CallbackInfo &info) {
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

  if (algorithm < 0 || algorithm > 3) {
    return Napi::Number::New(env, BAD_ARGUMENT);
  }

  // Get expected key and signature sizes
  int expectedPkSize = 0;
  int expectedSigSize = 0;

  switch (algorithm) {
  case 0:
    expectedPkSize = SECP256K1_PK_SIZE;
    expectedSigSize = SECP256K1_SIG_SIZE;
    break;
  case 1:
    expectedPkSize = ML_DSA_44_PK_SIZE;
    expectedSigSize = ML_DSA_44_SIG_SIZE;
    break;
  case 2:
    expectedPkSize = SLH_DSA_SHAKE_128S_PK_SIZE;
    expectedSigSize = SLH_DSA_SHAKE_128S_SIG_SIZE;
    break;
  default:
    return Napi::Number::New(env, BAD_ARGUMENT);
  }

  // Check key and signature sizes
  if (publicKey.ByteLength() != expectedPkSize) {
    return Napi::Number::New(env, BAD_KEY);
  }

  if (signature.ByteLength() != expectedSigSize) {
    return Napi::Number::New(env, BAD_SIGNATURE);
  }

  // In a real implementation, this would verify the signature
  // Here we're just pretending it's valid
  return Napi::Number::New(env, OK);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("bitcoin_pqc_public_key_size",
              Napi::Function::New(env, GetPublicKeySize));
  exports.Set("bitcoin_pqc_secret_key_size",
              Napi::Function::New(env, GetSecretKeySize));
  exports.Set("bitcoin_pqc_signature_size",
              Napi::Function::New(env, GetSignatureSize));
  exports.Set("bitcoin_pqc_keygen", Napi::Function::New(env, GenerateKeypair));
  exports.Set("bitcoin_pqc_sign", Napi::Function::New(env, SignMessage));
  exports.Set("bitcoin_pqc_verify", Napi::Function::New(env, VerifySignature));
  return exports;
}

NODE_API_MODULE(mock_bitcoinpqc, Init)
