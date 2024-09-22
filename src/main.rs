use heed::EnvFlags;
use std::{fs::create_dir_all, time::Instant};
use uuid::Uuid;

const ITEMS: usize = 11_000_000;

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
    k.clear();
    v.clear();
    
    k.extend(blake2sum(&Uuid::new_v4().as_u128().to_be_bytes()).to_vec());
    k.extend(Uuid::new_v4().as_u128().to_be_bytes());

    v.extend(&k);
    v.push(0u8);
}

fn main() {
    let mut key: Vec<u8> = Vec::new();
    let mut val: Vec<u8> = Vec::with_capacity(100);

    if std::env::args().any(|x| x.contains("--heed")) {
        println!("-- heed --");
        create_dir_all("heed").unwrap();

        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(20_000_000_000)
                .flags(EnvFlags::NO_SYNC | EnvFlags::NO_READ_AHEAD)
                .open("heed")
                .unwrap()
        };

        let mut wtx = env.write_txn().unwrap();
        let db: heed::Database<heed::types::Bytes, heed::types::Bytes> =
            env.create_database(&mut wtx, None).unwrap();
        wtx.commit().unwrap();

        let start = Instant::now();
        for idx in 0..ITEMS {
            kv(&mut key, &mut val):

            let mut wtx = env.write_txn().unwrap();
            db.put(&mut wtx, &key, &val).unwrap();
            wtx.commit().unwrap();

            if idx % 1_000_000 == 0 {
                println!("{idx}");
            }
        }
        println!("done in {:?}", start.elapsed());
    } else {
        println!("-- fjall --");

        let keyspace = fjall::Config::default().temporary(true).open().unwrap();
        let db = keyspace
            .open_partition("block_refs", Default::default())
            .unwrap();

        let start = Instant::now();
        for idx in 0..ITEMS {
            kv(&mut key, &mut val):

            db.insert(&key, &val).unwrap();

            if idx % 1_000_000 == 0 {
                println!("{idx}");
            }
        }
        println!("done in {:?}", start.elapsed());
    }
}
