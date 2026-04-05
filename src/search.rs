use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
};
use bitcoin::{secp256k1::SecretKey, Network};
use crossbeam_channel::bounded;

use crate::{
    address::{build_found_addr, generate_address, generate_address_merkle, FoundAddr},
    types::AddrType,
};

/// Batch size for thread-local attempt counting before flushing to the shared
/// atomic. Reduces cache-line contention across cores.
const ATTEMPT_BATCH: u64 = 4096;

// ── Session ───────────────────────────────────────────────────────────────────

pub struct Session {
    pub total_attempts: u64,
    pub total_elapsed:  f64,
}

impl Session {
    pub fn new() -> Self { Self { total_attempts: 0, total_elapsed: 0.0 } }
    pub fn record_run(&mut self, attempts: u64, elapsed: f64) {
        self.total_attempts += attempts;
        self.total_elapsed  += elapsed;
    }
}

// ── Worker spawner ────────────────────────────────────────────────────────────

pub fn spawn_workers(
    threads:     usize,
    addr_type:   AddrType,
    network:     Network,
    merkle_root: Option<bitcoin::taproot::TapNodeHash>,
    matcher:     Arc<dyn Fn(&str) -> bool + Send + Sync>,
    count:       usize,
    attempts:    Arc<AtomicU64>,
    found_count: Arc<AtomicU64>,
    done:        Arc<AtomicBool>,
    tx:          crossbeam_channel::Sender<FoundAddr>,
) {
    let use_merkle = addr_type == AddrType::Taproot && merkle_root.is_some();

    for _ in 0..threads {
        let matcher     = Arc::clone(&matcher);
        let attempts    = Arc::clone(&attempts);
        let found_count = Arc::clone(&found_count);
        let done        = Arc::clone(&done);
        let tx          = tx.clone();
        let need        = count;

        thread::spawn(move || {
            use bitcoin::secp256k1::rand::thread_rng;
            let mut rng = thread_rng();
            let mut local_count: u64 = 0;

            while !done.load(Ordering::Relaxed) {
                let secret = SecretKey::new(&mut rng);
                let addr_raw = if use_merkle {
                    generate_address_merkle(&secret, merkle_root, network)
                } else {
                    generate_address(&secret, addr_type, network)
                };

                local_count += 1;
                if local_count % ATTEMPT_BATCH == 0 {
                    attempts.fetch_add(ATTEMPT_BATCH, Ordering::Relaxed);
                }

                if matcher(&addr_raw) {
                    let prev = found_count.fetch_add(1, Ordering::SeqCst);
                    if prev < need as u64 {
                        let found = build_found_addr(&secret, addr_raw, addr_type, network);
                        let _ = tx.send(found);
                        if prev + 1 >= need as u64 {
                            done.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            // Flush remaining local count
            attempts.fetch_add(local_count % ATTEMPT_BATCH, Ordering::Relaxed);
        });
    }
}

/// Create a bounded channel suitable for worker result collection.
pub fn make_channel(capacity: usize) -> (crossbeam_channel::Sender<FoundAddr>, crossbeam_channel::Receiver<FoundAddr>) {
    bounded(capacity)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    #[test]
    fn workers_find_bc1p_prefix() {
        let attempts    = Arc::new(AtomicU64::new(0));
        let found_count = Arc::new(AtomicU64::new(0));
        let done        = Arc::new(AtomicBool::new(false));
        let (tx, rx)    = make_channel(16);

        let matcher: Arc<dyn Fn(&str) -> bool + Send + Sync> =
            Arc::new(|addr: &str| addr.starts_with("bc1p"));

        spawn_workers(
            2, AddrType::Taproot, Network::Bitcoin, None,
            matcher, 1,
            Arc::clone(&attempts), Arc::clone(&found_count),
            Arc::clone(&done), tx,
        );

        let found = rx.recv_timeout(Duration::from_secs(10))
            .expect("Should find a bc1p address within 10s");

        assert!(found.address.starts_with("bc1p"));
        assert_eq!(found.mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn session_accumulates_stats() {
        let mut s = Session::new();
        s.record_run(1_000_000, 2.5);
        s.record_run(500_000, 1.0);
        assert_eq!(s.total_attempts, 1_500_000);
        assert!((s.total_elapsed - 3.5).abs() < 0.0001);
    }
}
