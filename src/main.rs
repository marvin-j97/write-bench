use heed::EnvFlags;
use std::{fs::create_dir_all, time::Instant};
use uuid::Uuid;

/// Compute the blake2 of a slice
pub fn blake2sum(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b512, Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize()[..32]);

    hash
}

fn main() {
    let mut key: Vec<u8> = Vec::new();
    let mut val: Vec<u8> = Vec::with_capacity(100);

    println!("-- heed --");
    create_dir_all("heed").unwrap();

    let env = unsafe {
        heed::EnvOpenOptions::new()
            .map_size(16_000_000_000)
            .flags(EnvFlags::NO_SYNC | EnvFlags::NO_READ_AHEAD)
            .open("heed")
            .unwrap()
    };

    let mut wtx = env.write_txn().unwrap();
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> =
        env.create_database(&mut wtx, None).unwrap();
    wtx.commit().unwrap();

    let start = Instant::now();
    for idx in 0..11_000_000 {
        key.extend(blake2sum(&Uuid::new_v4().as_u128().to_be_bytes()).to_vec());
        key.extend(Uuid::new_v4().as_u128().to_be_bytes());

        val.extend(&key);
        val.push(0u8);

        let mut wtx = env.write_txn().unwrap();
        db.put(&mut wtx, &key, &val).unwrap();
        wtx.commit().unwrap();

        key.clear();
        val.clear();

        if idx % 1_000_000 == 0 {
            println!("{idx}");
        }
    }
    println!("done in {:?}", start.elapsed());

    println!("-- fjall --");

    let keyspace = fjall::Config::default().temporary(true).open().unwrap();
    let db = keyspace
        .open_partition("block_refs", Default::default())
        .unwrap();

    let start = Instant::now();
    for idx in 0..11_000_000 {
        key.extend(blake2sum(&Uuid::new_v4().as_u128().to_be_bytes()).to_vec());
        key.extend(Uuid::new_v4().as_u128().to_be_bytes());

        val.extend(&key);
        val.push(0u8);

        db.insert(&key, &val).unwrap();

        key.clear();
        val.clear();

        if idx % 1_000_000 == 0 {
            println!("{idx}");
        }
    }
    println!("done in {:?}", start.elapsed());
}
