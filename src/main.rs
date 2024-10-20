use std::{fs::create_dir_all, sync::Arc, time::Instant};

const ITEMS: usize = 10_000_000;
const CLEAN: bool = true;
const ZIPF_E: f64 = 1.2;

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Compute the blake2 of a slice
pub fn blake2sum(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b512, Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize()[..32]);

    hash
}

fn kv(k: &mut Vec<u8>, v: &mut Vec<u8>) {
    use uuid::Uuid;

    k.clear();
    v.clear();

    let pk = blake2sum(&Uuid::new_v4().as_u128().to_be_bytes()).to_vec();
    let sk = Uuid::new_v4().as_u128().to_be_bytes();

    k.extend(&pk);
    k.extend(&sk);

    v.extend(&pk);
    v.extend(&sk);
    v.push(0u8);
}

fn main() {
    let mut key: Vec<u8> = Vec::new();
    let mut val: Vec<u8> = Vec::with_capacity(100);

    // NOTE: We need to memorize some keys to read back
    let mut keys = Vec::with_capacity(ITEMS / 100);

    if std::env::args().any(|x| x.contains("--heed")) {
        println!("-- heed --");

        create_dir_all("heed").unwrap();

        let env = unsafe {
            use heed::EnvFlags;

            heed::EnvOpenOptions::new()
                .map_size(24_000_000_000)
                .flags(EnvFlags::NO_SYNC | EnvFlags::NO_READ_AHEAD)
                .open("heed")
                .unwrap()
        };

        let mut wtx = env.write_txn().unwrap();
        let db: heed::Database<heed::types::Bytes, heed::types::Bytes> =
            env.create_database(&mut wtx, None).unwrap();
        wtx.commit().unwrap();

        {
            println!("-- write --");

            let start = Instant::now();

            for idx in 0..ITEMS {
                kv(&mut key, &mut val);

                let mut wtx = env.write_txn().unwrap();
                db.put(&mut wtx, &key, &val).unwrap();
                wtx.commit().unwrap();

                if idx % 100 == 0 {
                    keys.push(key.clone());
                }

                if idx > 0 && idx % 1_000_000 == 0 {
                    let elapsed = start.elapsed();
                    let ns_per_item = elapsed.as_nanos() / idx as u128;
                    println!(
                        "{idx} after {:?}, avg={:?}",
                        start.elapsed(),
                        std::time::Duration::from_nanos(ns_per_item as u64)
                    );
                }
            }

            let elapsed = start.elapsed();
            let ns_per_item = elapsed.as_nanos() / ITEMS as u128;
            println!(
                "done in {elapsed:?}, avg={:?}",
                std::time::Duration::from_nanos(ns_per_item as u64)
            );
        }

        {
            println!("-- read --");

            let mut rng = rand::thread_rng();
            let zipf = zipf::ZipfDistribution::new(keys.len() - 1, ZIPF_E).unwrap();

            let start = Instant::now();

            for idx in 0..20_000_000 {
                use rand::distributions::Distribution;

                let sample = zipf.sample(&mut rng);
                let key = &keys[sample];

                let rtx = env.read_txn().unwrap();
                db.get(&rtx, key).unwrap().unwrap();

                if idx > 0 && idx % 1_000_000 == 0 {
                    let elapsed = start.elapsed();
                    let ns_per_item = elapsed.as_nanos() / idx as u128;
                    println!(
                        "{idx} after {:?}, avg={:?}",
                        start.elapsed(),
                        std::time::Duration::from_nanos(ns_per_item as u64)
                    );
                }
            }

            let elapsed = start.elapsed();
            let ns_per_item = elapsed.as_nanos() / ITEMS as u128;
            println!(
                "done in {elapsed:?}, avg={:?}",
                std::time::Duration::from_nanos(ns_per_item as u64)
            );
        }

        if CLEAN {
            std::fs::remove_dir_all("heed").unwrap();
        }
    } else if std::env::args().any(|x| x.contains("--fjall")) {
        use fjall::BlockCache;

        println!("-- fjall --");

        let keyspace = fjall::Config::default()
            .block_cache(Arc::new(BlockCache::with_capacity_bytes(128_000_000)))
            .temporary(CLEAN)
            .open()
            .unwrap();

        let db = keyspace
            .open_partition("block_refs", Default::default())
            .unwrap();

        {
            println!("-- write --");

            let start = Instant::now();
            for idx in 0..ITEMS {
                kv(&mut key, &mut val);

                db.insert(&key, &val).unwrap();

                if idx % 100 == 0 {
                    keys.push(key.clone());
                }

                if idx > 0 && idx % 1_000_000 == 0 {
                    let elapsed = start.elapsed();
                    let ns_per_item = elapsed.as_nanos() / idx as u128;
                    println!(
                        "{idx} after {:?}, avg={:?}",
                        start.elapsed(),
                        std::time::Duration::from_nanos(ns_per_item as u64)
                    );
                }
            }

            let elapsed = start.elapsed();
            let ns_per_item = elapsed.as_nanos() / ITEMS as u128;
            println!(
                "done in {elapsed:?}, avg={:?}",
                std::time::Duration::from_nanos(ns_per_item as u64)
            );
        }

        {
            println!("-- read --");

            let mut rng = rand::thread_rng();
            let zipf = zipf::ZipfDistribution::new(keys.len() - 1, ZIPF_E).unwrap();

            let start = Instant::now();

            for idx in 0..(ITEMS * 2) {
                use rand::distributions::Distribution;

                let sample = zipf.sample(&mut rng);
                let key = &keys[sample];

                db.get(key).unwrap().unwrap();

                if idx > 0 && idx % 1_000_000 == 0 {
                    let elapsed = start.elapsed();
                    let ns_per_item = elapsed.as_nanos() / idx as u128;
                    println!(
                        "{idx} after {:?}, avg={:?}",
                        start.elapsed(),
                        std::time::Duration::from_nanos(ns_per_item as u64)
                    );
                }
            }

            let elapsed = start.elapsed();
            let ns_per_item = elapsed.as_nanos() / (ITEMS * 2) as u128;
            println!(
                "done in {elapsed:?}, avg={:?}",
                std::time::Duration::from_nanos(ns_per_item as u64)
            );
        }
    } else if std::env::args().any(|x| x.contains("--canopy")) {
        use canopydb::Database;

        println!("-- canopydb --");

        create_dir_all("canopydb").unwrap();

        let mut opts = canopydb::EnvOptions::new("canopydb");
        opts.disable_fsync = true;
        opts.page_cache_size = 128_000_000;

        let db = Database::with_options(opts, canopydb::DbOptions::default()).unwrap();

        let tx = db.begin_write().unwrap();
        {
            let _tree = tx.get_or_create_tree(b"default").unwrap();
        }
        tx.commit().unwrap();

        {
            println!("-- write --");

            let start = Instant::now();
            for idx in 0..ITEMS {
                kv(&mut key, &mut val);

                let tx = db.begin_write().unwrap();
                {
                    let mut tree = tx.get_or_create_tree(b"default").unwrap();
                    tree.insert(&key, &val).unwrap();
                }
                tx.commit().unwrap();

                if idx % 100 == 0 {
                    keys.push(key.clone());
                }

                if idx > 0 && idx % 1_000_000 == 0 {
                    let elapsed = start.elapsed();
                    let ns_per_item = elapsed.as_nanos() / idx as u128;
                    println!(
                        "{idx} after {:?}, avg={:?}",
                        start.elapsed(),
                        std::time::Duration::from_nanos(ns_per_item as u64)
                    );
                }
            }

            let elapsed = start.elapsed();
            let ns_per_item = elapsed.as_nanos() / ITEMS as u128;
            println!(
                "done in {elapsed:?}, avg={:?}",
                std::time::Duration::from_nanos(ns_per_item as u64)
            );
        }

        {
            println!("-- read --");

            let mut rng = rand::thread_rng();
            let zipf = zipf::ZipfDistribution::new(keys.len() - 1, ZIPF_E).unwrap();

            let start = Instant::now();

            for idx in 0..(ITEMS * 2) {
                use rand::distributions::Distribution;

                let sample = zipf.sample(&mut rng);
                let key = &keys[sample];

                {
                    let rx = db.begin_read().unwrap();
                    let tree = rx.get_tree(b"default").unwrap().unwrap();
                    tree.get(key).unwrap().unwrap();
                }

                if idx > 0 && idx % 1_000_000 == 0 {
                    let elapsed = start.elapsed();
                    let ns_per_item = elapsed.as_nanos() / idx as u128;
                    println!(
                        "{idx} after {:?}, avg={:?}",
                        start.elapsed(),
                        std::time::Duration::from_nanos(ns_per_item as u64)
                    );
                }
            }

            let elapsed = start.elapsed();
            let ns_per_item = elapsed.as_nanos() / (ITEMS * 2) as u128;
            println!(
                "done in {elapsed:?}, avg={:?}",
                std::time::Duration::from_nanos(ns_per_item as u64)
            );
        }

        if CLEAN {
            std::fs::remove_dir_all("canopydb").unwrap();
        }
    }
}
