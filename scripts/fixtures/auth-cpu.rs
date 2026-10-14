use std::io::{Read, Write};
use std::time::Instant;
use underlay_auth::hashing::{Argon2Hasher, PasswordHasherExt, PasswordVerifierExt};

fn phase(name: &str, started: Instant, outcome: &str) {
    println!("{{\"phase\":\"{name}\",\"elapsed_us\":{},\"outcome\":\"{outcome}\"}}", started.elapsed().as_micros());
    let _ = std::io::stdout().flush();
}

fn main() {
    // No panic payload, secret, salt, PHC or error Display ever reaches output.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("{{\"kind\":\"panic\"}}");
    }));
    let total = Instant::now();
    let mut password = vec![0u8; 32];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut password)).is_err() {
        phase("preparation", total, "random_error");
        std::process::exit(1);
    }
    let hasher = Argon2Hasher::with_params(131072, 4, 4);
    let hash_started = Instant::now();
    let phc = match hasher.hash_password(&password) {
        Ok(value) => value,
        Err(_) => { phase("hash", hash_started, "error"); std::process::exit(1); }
    };
    phase("hash", hash_started, "completed");
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(value) => value,
        Err(_) => { phase("runtime", total, "error"); std::process::exit(1); }
    };
    let scheduled = Instant::now();
    phase("schedule", scheduled, "started");
    let ok = runtime.block_on(async {
        let joined = tokio::task::spawn_blocking(move || {
            phase("worker_entry", scheduled, "started");
            let verification = Instant::now();
            let result = hasher.verify_password(&password, &phc);
            phase("verification", verification, match &result {
                Ok(true) => "valid", Ok(false) => "invalid", Err(_) => "error",
            });
            result
        }).await;
        match joined {
            Ok(result) => { phase("join", scheduled, "completed"); matches!(result, Ok(true)) }
            Err(error) => {
                phase("join", scheduled, if error.is_panic() { "panic" } else { "cancelled" });
                false
            }
        }
    });
    phase("total", total, if ok { "valid" } else { "error" });
    if !ok { std::process::exit(1); }
}
