import {
  Algorithm,
  generateKeyPair,
  sign,
  verify,
  publicKeySize,
  secretKeySize,
  signatureSize,
} from "../src";
import crypto from "crypto";

/**
 * This example demonstrates basic usage of the bitcoinpqc TypeScript bindings
 * with SLH-DSA-SHAKE-128S (SPHINCS+).
 *
 * It shows:
 * 1. Getting key and signature sizes for SLH-DSA
 * 2. Key generation
 * 3. Signing messages
 * 4. Verifying signatures
 * 5. Error handling
 */

// Print key sizes for SLH-DSA algorithm
console.log("===== SLH-DSA Key and Signature Sizes =====");
const algo = Algorithm.SLH_DSA_SHAKE_128S;
const algoName = Algorithm[algo];
console.log(`${algoName}:`);
console.log(`  Public key size: ${publicKeySize(algo)} bytes`);
console.log(`  Secret key size: ${secretKeySize(algo)} bytes`);
console.log(`  Signature size: ${signatureSize(algo)} bytes`);
console.log();

// Generate a keypair and demonstrate SLH-DSA functionality
function demonstrateSlhDsa(): void {
  console.log(`===== Working with ${Algorithm[Algorithm.SLH_DSA_SHAKE_128S]} =====`);

  // Generate random data for key generation
  console.log("Generating random data...");
  const randomData = crypto.randomBytes(128);

  try {
    // Generate a keypair
    console.log("Generating SLH-DSA keypair...");
    const keypair = generateKeyPair(Algorithm.SLH_DSA_SHAKE_128S, randomData);
    console.log(
      `Generated keypair with public key size ${keypair.publicKey.bytes.length} bytes`
    );

    // Create a message to sign
    const message = "Hello from SLH-DSA-SHAKE-128S (SPHINCS+)!";
    const messageBytes = Buffer.from(message, "utf-8");
    console.log(`Message to sign: "${message}"`);

    // Sign the message
    console.log("Signing message...");
    const signature = sign(keypair.secretKey, messageBytes);
    console.log(`Created signature of size ${signature.bytes.length} bytes`);

    // Verify the signature
    console.log("Verifying signature...");
    try {
      verify(keypair.publicKey, messageBytes, signature);
      console.log("✅ Signature verified successfully!");
    } catch (error) {
      console.error("❌ Signature verification failed:", error);
    }

    // Try verifying with a different message (should fail)
    const badMessage = Buffer.from(message + " (modified)", "utf-8");
    console.log(
      `\nAttempting to verify with modified message: "${message} (modified)"`
    );
    try {
      verify(keypair.publicKey, badMessage, signature);
      console.log("❌ Verification succeeded with modified message!");
    } catch (error) {
      console.log("✅ Verification correctly failed with modified message");
      console.log(`   Error: ${error}`);
    }
  } catch (error) {
    console.error(
      `❌ Error while working with ${Algorithm[Algorithm.SLH_DSA_SHAKE_128S]}:`,
      error
    );
  }

  console.log("\n");
}

// Run the SLH-DSA demonstration
demonstrateSlhDsa();
