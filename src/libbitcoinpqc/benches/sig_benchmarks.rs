use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rng, RngCore};

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm};

// Set to true to enable debug output, false to disable
const DEBUG_MODE: bool = false;

// Global storage for sizes
static SIZE_RESULTS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

// Helper function to get or initialize the size results
fn get_size_results() -> &'static Mutex<HashMap<String, usize>> {
    SIZE_RESULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

// Conditional debug print macro
macro_rules! debug_println {
    ($($arg:tt)*) => {
        if DEBUG_MODE {
            println!($($arg)*);
        }
    };
}

// Get random data of a specified size
fn get_random_data(size: usize) -> Vec<u8> {
    let mut random_data = vec![0u8; size];
    rng().fill_bytes(&mut random_data);
    random_data
}

// Configure benchmark group with common settings
fn configure_group(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    group.measurement_time(Duration::from_secs(10));
}

// Helper function to store size results
fn store_size_result(name: &str, value: usize) {
    let results = get_size_results();
    let mut results = results.lock().unwrap();
    results.insert(name.to_string(), value);
}

// ML-DSA-44 BENCHMARKS

fn bench_ml_dsa_44_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_keygen");
    configure_group(&mut group);

    group.bench_function("ML_DSA_44", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap()
        });
    });

    group.finish();
}

fn bench_ml_dsa_44_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_signing");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap();

    group.bench_function("ML_DSA_44", |b| {
        b.iter(|| sign(&ml_keypair.secret_key, message));
    });

    group.finish();
}

fn bench_ml_dsa_44_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_verification");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap();
    let ml_sig = sign(&ml_keypair.secret_key, message).unwrap();

    group.bench_function("ML_DSA_44", |b| {
        b.iter(|| verify(&ml_keypair.public_key, message, &ml_sig).unwrap());
    });

    group.finish();
}

// SLH-DSA-128S BENCHMARKS

fn bench_slh_dsa_128s_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_keygen");
    configure_group(&mut group);
    group.sample_size(10); // Reduce sample count for SLH-DSA which is slower

    group.bench_function("SLH_DSA_128S", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap()
        });
    });

    group.finish();
}

fn bench_slh_dsa_128s_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_signing");
    configure_group(&mut group);
    group.sample_size(10); // Reduce sample count for SLH-DSA which is slower

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap();

    group.bench_function("SLH_DSA_128S", |b| {
        b.iter(|| sign(&slh_keypair.secret_key, message));
    });

    group.finish();
}

fn bench_slh_dsa_128s_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_verification");
    configure_group(&mut group);
    group.sample_size(10); // Reduce sample count for SLH-DSA which is slower

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap();
    let slh_sig = sign(&slh_keypair.secret_key, message).unwrap();

    group.bench_function("SLH_DSA_128S", |b| {
        b.iter(|| verify(&slh_keypair.public_key, message, &slh_sig).unwrap());
    });

    group.finish();
}

// SIZE REPORTING - Combined in one benchmark

fn bench_sizes(c: &mut Criterion) {
    let group = c.benchmark_group("sizes");

    let message = b"This is a test message for benchmarking";

    // ML-DSA-44
    let random_data = get_random_data(256);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap();
    let ml_sig = sign(&ml_keypair.secret_key, message).unwrap();
    let ml_pk_size = ml_keypair.public_key.bytes.len();
    let ml_sk_size = ml_keypair.secret_key.bytes.len();
    let ml_sig_size = ml_sig.bytes.len();
    let ml_pk_sig_size = ml_pk_size + ml_sig_size;

    // Store size results
    store_size_result("ml_dsa_44_pubkey", ml_pk_size);
    store_size_result("ml_dsa_44_seckey", ml_sk_size);
    store_size_result("ml_dsa_44_sig", ml_sig_size);
    store_size_result("ml_dsa_44_pk_sig", ml_pk_sig_size);

    // SLH-DSA-128S
    let random_data = get_random_data(256);
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap();
    let slh_sig = sign(&slh_keypair.secret_key, message).unwrap();
    let slh_pk_size = slh_keypair.public_key.bytes.len();
    let slh_sk_size = slh_keypair.secret_key.bytes.len();
    let slh_sig_size = slh_sig.bytes.len();
    let slh_pk_sig_size = slh_pk_size + slh_sig_size;

    // Store size results
    store_size_result("slh_dsa_128s_pubkey", slh_pk_size);
    store_size_result("slh_dsa_128s_seckey", slh_sk_size);
    store_size_result("slh_dsa_128s_sig", slh_sig_size);
    store_size_result("slh_dsa_128s_pk_sig", slh_pk_sig_size);

    // Print key and signature sizes
    debug_println!("Key and Signature Sizes (bytes):");
    debug_println!("ML-DSA-44:");
    debug_println!(
        "  Public key: {}, Secret key: {}, Signature: {}",
        ml_pk_size,
        ml_sk_size,
        ml_sig_size
    );

    debug_println!("SLH-DSA-128S:");
    debug_println!(
        "  Public key: {}, Secret key: {}, Signature: {}",
        slh_pk_size,
        slh_sk_size,
        slh_sig_size
    );

    group.finish();
}

// Function to generate the markdown report by updating existing file
fn generate_report(_c: &mut Criterion) {
    let report_path = "benches/REPORT.md";
    let mut report_content = String::new();

    // Try to read the existing report file
    match File::open(report_path) {
        Ok(mut file) => {
            if file.read_to_string(&mut report_content).is_err() {
                eprintln!(
                    "Error reading existing report file: {}. Creating a new one.",
                    report_path
                );
                report_content.clear();
            }
        }
        Err(_) => {
            println!("Report file {} not found. Creating a new one.", report_path);
        }
    }

    // Get size results
    let size_results = get_size_results();
    let size_results = size_results.lock().unwrap();

    // --- Parse existing secp256k1 values or use defaults ---
    let mut secp_pubkey_size = 32; // Default
    let mut secp_seckey_size = 32; // Default
    let mut secp_sig_size = 64; // Default
    let mut secp_pk_sig_size = secp_pubkey_size + secp_sig_size; // Default derived

    // Find and parse secp256k1 sizes from the report if available
    if let Some(line) = report_content
        .lines()
        .find(|l| l.starts_with("| secp256k1 |"))
    {
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        // Expecting format: | secp256k1 | SK bytes (rel) | PK bytes (rel) | Sig bytes (rel) | PK+Sig bytes (rel) |
        if parts.len() > 5 {
            // Parse Secret Key Size (Column 2)
            if let Ok(sk) = parts[2]
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<usize>()
            {
                secp_seckey_size = sk;
            }
            // Parse Public Key Size (Column 3)
            if let Ok(pk) = parts[3]
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<usize>()
            {
                secp_pubkey_size = pk;
            }
            // Parse Signature Size (Column 4)
            if let Ok(sig) = parts[4]
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<usize>()
            {
                secp_sig_size = sig;
            }
            // Recalculate combined size based on parsed values (Column 5 is derived)
            secp_pk_sig_size = secp_pubkey_size + secp_sig_size;
        } else {
            println!(
                "Warning: Found secp256k1 line but failed to parse sizes correctly from: {}",
                line
            );
        }
    }

    // --- Process lines and update size table ---
    let mut updated_lines = Vec::new();
    let mut in_size_table = false;
    let mut size_table_header_found = false;
    // Define the expected header and separator for the size table (matching the commit diff)
    let size_table_header =
        "| Algorithm | Secret Key | Public Key | Signature | Public Key + Signature |";
    let size_table_separator =
        "|-----------|------------|------------|-----------|------------------------|";

    for line in report_content.lines() {
        let mut line_to_push = line.to_string(); // Default to original line
        let trimmed_line = line.trim();

        // Detect entering/leaving the size table
        if trimmed_line == size_table_separator && size_table_header_found {
            in_size_table = true; // Mark start of data rows
        } else if trimmed_line == size_table_header {
            size_table_header_found = true; // Found the header
        } else if trimmed_line.is_empty() || trimmed_line.starts_with("#") {
            // Stop processing table rows if we hit an empty line or a new section header
            if in_size_table {
                in_size_table = false;
                size_table_header_found = false; // Reset for potential future tables
            }
        }

        // Update rows within the size table
        if in_size_table {
            if trimmed_line.starts_with("| secp256k1 |") {
                // Format the secp256k1 line using parsed/default values
                line_to_push = format!(
                    "| secp256k1 | {} bytes (1.00x) | {} bytes (1.00x) | {} bytes (1.00x) | {} bytes (1.00x) |",
                    secp_seckey_size, secp_pubkey_size, secp_sig_size, secp_pk_sig_size
                );
            } else if trimmed_line.starts_with("| ML-DSA-44 |") {
                let ml_pubkey_size = size_results.get("ml_dsa_44_pubkey").cloned().unwrap_or(0);
                let ml_seckey_size = size_results.get("ml_dsa_44_seckey").cloned().unwrap_or(0);
                let ml_sig_size = size_results.get("ml_dsa_44_sig").cloned().unwrap_or(0);
                let ml_pk_sig_size = size_results.get("ml_dsa_44_pk_sig").cloned().unwrap_or(0);
                line_to_push = format!(
                    "| ML-DSA-44 | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) |",
                    ml_seckey_size, if secp_seckey_size > 0 { ml_seckey_size as f64 / secp_seckey_size as f64 } else { 0.0 },
                    ml_pubkey_size, if secp_pubkey_size > 0 { ml_pubkey_size as f64 / secp_pubkey_size as f64 } else { 0.0 },
                    ml_sig_size, if secp_sig_size > 0 { ml_sig_size as f64 / secp_sig_size as f64 } else { 0.0 },
                    ml_pk_sig_size, if secp_pk_sig_size > 0 { ml_pk_sig_size as f64 / secp_pk_sig_size as f64 } else { 0.0 }
                );
            } else if trimmed_line.starts_with("| SLH-DSA-128S |") {
                let slh_pubkey_size = size_results
                    .get("slh_dsa_128s_pubkey")
                    .cloned()
                    .unwrap_or(0);
                let slh_seckey_size = size_results
                    .get("slh_dsa_128s_seckey")
                    .cloned()
                    .unwrap_or(0);
                let slh_sig_size = size_results.get("slh_dsa_128s_sig").cloned().unwrap_or(0);
                let slh_pk_sig_size = size_results
                    .get("slh_dsa_128s_pk_sig")
                    .cloned()
                    .unwrap_or(0);
                line_to_push = format!(
                    "| SLH-DSA-128S | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) |",
                    slh_seckey_size, if secp_seckey_size > 0 { slh_seckey_size as f64 / secp_seckey_size as f64 } else { 0.0 },
                    slh_pubkey_size, if secp_pubkey_size > 0 { slh_pubkey_size as f64 / secp_pubkey_size as f64 } else { 0.0 },
                    slh_sig_size, if secp_sig_size > 0 { slh_sig_size as f64 / secp_sig_size as f64 } else { 0.0 },
                    slh_pk_sig_size, if secp_pk_sig_size > 0 { slh_pk_sig_size as f64 / secp_pk_sig_size as f64 } else { 0.0 }
                );
            }
            // Note: Any other lines within the size table block will keep their original content (e.g., comments)
        }

        updated_lines.push(line_to_push);
    }

    // --- Generate default report if needed ---
    // If the report was empty or didn't contain the expected size table header, generate a default one.
    if report_content.is_empty() || !report_content.contains(size_table_header) {
        println!("Generating default report structure in {}.", report_path);
        updated_lines.clear(); // Start fresh

        // Default Header
        updated_lines
            .push("# Benchmark Report: Post-Quantum Cryptography vs secp256k1".to_string());
        updated_lines.push("\nThis report compares the performance and size characteristics of post-quantum cryptographic algorithms with secp256k1.\n".to_string());

        // Default Performance section (with placeholders)
        updated_lines.push("## Performance Comparison\n".to_string());
        updated_lines.push(
            "All values show relative performance compared to secp256k1 (lower is better).\n"
                .to_string(),
        );
        updated_lines.push("| Algorithm | Key Generation | Signing | Verification |".to_string());
        updated_lines.push("|-----------|----------------|---------|--------------|".to_string());
        updated_lines.push("| secp256k1 | 1.00x | 1.00x | 1.00x |".to_string());
        updated_lines
            .push("| ML-DSA-44 | *Needs Update* | *Needs Update* | *Needs Update* |".to_string()); // Placeholders
        updated_lines.push(
            "| SLH-DSA-128S | *Needs Update* | *Needs Update* | *Needs Update* |".to_string(),
        ); // Placeholders
        updated_lines.push("\n*Note: Performance values require parsing Criterion output and are not yet updated automatically.*".to_string());

        // Default Size section (using current data and new format)
        updated_lines.push("\n## Size Comparison\n".to_string());
        updated_lines.push(
            "All values show actual sizes with relative comparison to secp256k1.\n".to_string(),
        );
        updated_lines.push(size_table_header.to_string()); // Use the defined header
        updated_lines.push(size_table_separator.to_string()); // Use the defined separator

        // secp line
        updated_lines.push(format!(
            "| secp256k1 | {} bytes (1.00x) | {} bytes (1.00x) | {} bytes (1.00x) | {} bytes (1.00x) |",
            secp_seckey_size, secp_pubkey_size, secp_sig_size, secp_pk_sig_size
        ));

        // ML-DSA line
        let ml_pubkey_size = size_results.get("ml_dsa_44_pubkey").cloned().unwrap_or(0);
        let ml_seckey_size = size_results.get("ml_dsa_44_seckey").cloned().unwrap_or(0);
        let ml_sig_size = size_results.get("ml_dsa_44_sig").cloned().unwrap_or(0);
        let ml_pk_sig_size = size_results.get("ml_dsa_44_pk_sig").cloned().unwrap_or(0);
        updated_lines.push(format!(
            "| ML-DSA-44 | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) |",
            ml_seckey_size, if secp_seckey_size > 0 { ml_seckey_size as f64 / secp_seckey_size as f64 } else { 0.0 },
            ml_pubkey_size, if secp_pubkey_size > 0 { ml_pubkey_size as f64 / secp_pubkey_size as f64 } else { 0.0 },
            ml_sig_size, if secp_sig_size > 0 { ml_sig_size as f64 / secp_sig_size as f64 } else { 0.0 },
            ml_pk_sig_size, if secp_pk_sig_size > 0 { ml_pk_sig_size as f64 / secp_pk_sig_size as f64 } else { 0.0 }
        ));

        // SLH-DSA line
        let slh_pubkey_size = size_results
            .get("slh_dsa_128s_pubkey")
            .cloned()
            .unwrap_or(0);
        let slh_seckey_size = size_results
            .get("slh_dsa_128s_seckey")
            .cloned()
            .unwrap_or(0);
        let slh_sig_size = size_results.get("slh_dsa_128s_sig").cloned().unwrap_or(0);
        let slh_pk_sig_size = size_results
            .get("slh_dsa_128s_pk_sig")
            .cloned()
            .unwrap_or(0);
        updated_lines.push(format!(
            "| SLH-DSA-128S | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) | {} bytes ({:.2}x) |",
            slh_seckey_size, if secp_seckey_size > 0 { slh_seckey_size as f64 / secp_seckey_size as f64 } else { 0.0 },
            slh_pubkey_size, if secp_pubkey_size > 0 { slh_pubkey_size as f64 / secp_pubkey_size as f64 } else { 0.0 },
            slh_sig_size, if secp_sig_size > 0 { slh_sig_size as f64 / secp_sig_size as f64 } else { 0.0 },
            slh_pk_sig_size, if secp_pk_sig_size > 0 { slh_pk_sig_size as f64 / secp_pk_sig_size as f64 } else { 0.0 }
        ));

        // Default Summary
        updated_lines.push("\n## Summary\n".to_string());
        updated_lines.push("This benchmark comparison demonstrates the performance and size tradeoffs between post-quantum cryptographic algorithms and traditional elliptic curve cryptography (secp256k1).".to_string());
        updated_lines.push("\nWhile post-quantum algorithms generally have larger keys and signatures, they provide security against quantum computer attacks that could break elliptic curve cryptography.".to_string());
    }

    // --- Write updated content back to file ---
    match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(report_path)
    {
        Ok(mut file) => {
            let output_string = updated_lines.join("\n");
            if file.write_all(output_string.as_bytes()).is_err() {
                eprintln!("Error writing updated report to {}", report_path);
            } else {
                // Add a trailing newline if the content doesn't end with one
                if !output_string.ends_with('\n') {
                    if file.write_all(b"\n").is_err() {
                        eprintln!("Error writing trailing newline to {}", report_path);
                    }
                }
                println!("Report updated successfully: {}", report_path);
            }
        }
        Err(e) => {
            eprintln!("Failed to open {} for writing: {}", report_path, e);
        }
    }
}

// Organize the benchmarks by algorithm rather than by operation
criterion_group!(
    benches,
    bench_ml_dsa_44_keygen,
    bench_ml_dsa_44_signing,
    bench_ml_dsa_44_verification,
    bench_slh_dsa_128s_keygen,
    bench_slh_dsa_128s_signing,
    bench_slh_dsa_128s_verification,
    bench_sizes,
    generate_report
);
criterion_main!(benches);
