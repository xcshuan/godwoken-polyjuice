//! Test SimpleStorage
//!   See ./evm-contracts/SimpleStorage.sol

use crate::helper::{
    self, build_eth_l2_script, new_account_script, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use ethabi::{ethereum_types::U256, Contract, Token};
use gw_common::{
    blake2b::new_blake2b,
    smt::Blake2bHasher,
    sparse_merkle_tree::CompiledMerkleProof,
    state::{build_account_key, State},
    H256,
};
use gw_generator::{dummy_state::DummyState, traits::StateExt};
use gw_store::{chain_view::ChainView, traits::chain_store::ChainStore};
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
// use std::convert::TryInto;

const INIT_CODE: &str = include_str!("./evm-contracts/Unipass.bin");
const INIT_ABI: &str = include_str!("./evm-contracts/Unipass.abi");

#[test]
fn test_unipass_location() {
    // generate dummy state
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    // account_id is 3
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    // construct tx sender
    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    // account_id is 4
    let from_id = state.create_account_from_script(from_script).unwrap();

    // mint some token for gas
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 10000000)
        .unwrap();
    let from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance1);

    // Deploy Unipass contract
    {
        // block 1
        let block_info = new_block_info(0, 1, 0);
        // contract bytecode
        let input = hex::decode(INIT_CODE).unwrap();
        // polyjuice args
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        // L2 Tx
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(creator_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();

        // begin a rocksdb transaction
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        // execute_transactionso
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        // apply result
        state.apply_run_result(&run_result).expect("update state");
        // 557534 < 560K
        helper::check_cycles("Deploy Unipass", run_result.used_cycles, 2000000);
    }

    // get contract_account_script
    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    // get contract account_id 5
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let from_balance2 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance2);
    println!(
        "contract account script: {}",
        hex::encode(contract_account_script.as_slice())
    );
    println!(
        "eth address: {}",
        hex::encode(&contract_account_script.args().raw_data().as_ref()[36..])
    );

    // generate test user
    let email_0 = "test_0@test.com";
    let mut h = Sha256::new();
    h.update(email_0.as_bytes());
    let register_email_0 = h.finalize().to_vec();

    println!("register_email_0: {}", hex::encode(&register_email_0));

    // generate some random key
    let mut rng = rand::prelude::thread_rng();
    let mut rsa_key_0 = [0u8; 256];
    rng.fill_bytes(&mut rsa_key_0);

    println!("rsa_key_0: {}", hex::encode(&rsa_key_0));

    let mut k1_key_0 = [0u8; 20];
    rng.fill_bytes(&mut k1_key_0);

    println!("k1_key_0: {}", hex::encode(&k1_key_0));

    let mut r1_key_0 = [0u8; 64];
    rng.fill_bytes(&mut r1_key_0);

    println!("r1_key_0: {}", hex::encode(&r1_key_0));

    let u256_one = U256::from(1 as i32);

    let rsa_key_type = ethabi::Uint::from_str_radix("0", 10).unwrap();
    let k1_key_type = ethabi::Uint::from_str_radix("1", 10).unwrap();
    let r1_key_type = ethabi::Uint::from_str_radix("2", 10).unwrap();

    println!("Test register a user");
    {
        // Unipass.register;
        let block_info = new_block_info(0, 2, 0);
        let contract = Contract::load(INIT_ABI.as_bytes()).unwrap();

        // register use a rsa key, construct input
        let input = contract
            .function("register")
            .unwrap()
            .encode_input(&vec![
                Token::FixedBytes(register_email_0.clone()),
                Token::Uint(rsa_key_type),
                Token::Bytes(rsa_key_0.to_vec()),
                Token::String(String::from("TestUser_0")),
            ])
            .unwrap();

        // println!("input:{:?}", hex::encode(&input));

        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(1000000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();

        // println!("add firstkey raw_tx {:?}",raw_tx.as_slice());
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        let log_item = &run_result.logs[0];
        println!("Unipass log:{:?}", hex::encode(&log_item.data().raw_data()));
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles("Unipass test register", run_result.used_cycles, 2000_000);
    }

    let user_nonce_0 = ethabi::Uint::from_str_radix("2", 10).unwrap();
    println!("Add a secp256k1 key.");
    {
        // Unipass.addLocalKey
        let block_info = new_block_info(0, 3, 0);
        let contract = Contract::load(INIT_ABI.as_bytes()).unwrap();

        // add a k1 key
        let input = contract
            .function("addLocalKey")
            .unwrap()
            .encode_input(&vec![
                Token::FixedBytes(register_email_0.clone()),
                Token::Uint(user_nonce_0),
                Token::Uint(k1_key_type),
                Token::Bytes(k1_key_0.to_vec()),
            ])
            .unwrap();

        // println!("input:{:?}", hex::encode(&input));

        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(1000000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();

        // println!("add firstkey raw_tx {:?}",raw_tx.as_slice());
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        let log_item = &run_result.logs[0];
        println!("Unipass log:{:?}", hex::encode(&log_item.data().raw_data()));
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles("Unipass add a k1 Key", run_result.used_cycles, 2000_000);
    }

    println!("Add a secp256r1 key.");
    let user_nonce_0 = user_nonce_0.checked_add(u256_one).unwrap();
    {
        // Unipass.addKey(0x0d10);
        let block_info = new_block_info(0, 4, 0);
        let contract = Contract::load(INIT_ABI.as_bytes()).unwrap();

        // add second key
        let input = contract
            .function("addLocalKey")
            .unwrap()
            .encode_input(&vec![
                Token::FixedBytes(register_email_0.clone()),
                Token::Uint(user_nonce_0),
                Token::Uint(r1_key_type),
                Token::Bytes(r1_key_0.to_vec()),
            ])
            .unwrap();

        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(1000000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        let log_item = &run_result.logs[0];
        println!("Unipass log:{:?}", hex::encode(&log_item.data().raw_data()));
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles("Unipass add a r1 Key", run_result.used_cycles, 2000_000);
    }

    let email_1 = "test_1@test.com";
    let mut h = Sha256::new();
    h.update(email_1.as_bytes());
    let register_email_1 = h.finalize().to_vec();

    println!(
        "register_email_1: {:?}, register_email_1: {}",
        &register_email_1,
        hex::encode(&register_email_1)
    );

    // generate some random key
    let mut rsa_key_1 = [0u8; 256];
    rng.fill_bytes(&mut rsa_key_1);

    println!("register another key.");
    {
        // Unipass.regiser;
        let block_info = new_block_info(0, 5, 0);
        let contract = Contract::load(INIT_ABI.as_bytes()).unwrap();

        // register use a rsa key, construct input
        let input = contract
            .function("register")
            .unwrap()
            .encode_input(&vec![
                Token::FixedBytes(register_email_1.clone()),
                Token::Uint(rsa_key_type),
                Token::Bytes(rsa_key_1.to_vec()),
                Token::String(String::from("TestUser_1")),
            ])
            .unwrap();

        // println!("input:{:?}", hex::encode(&input));

        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(1000000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();

        // println!("add firstkey raw_tx {:?}",raw_tx.as_slice());
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        let log_item = &run_result.logs[0];
        println!("Unipass log:{:?}", hex::encode(&log_item.data().raw_data()));
        state.apply_run_result(&run_result).expect("update state");
        // 489767 < 500K
        helper::check_cycles(
            "Unipass register another key",
            run_result.used_cycles,
            2000_000,
        );
    }

    // mapping(bytes32 => UserInfo) public users;  slot 0
    // uint public totalUsers;			           slot 1
    // PubKey public admin;                        slot 2
    // uint8 public chainID;                       slot 3

    // 用户基本信息
    //  struct UserInfo {
    //     bytes32 register_email;        slot 0
    //     uint nonce;					  slot 1
    //     PubKey[] keys;				  slot 2
    // }

    // struct PubKey {
    //     uint keyType;    slot 0
    //     bytes key;       slot 1
    // }

    println!("User_0 infomation:");
    // verify first RSA key
    for (index, key_type) in (0..3).zip(0..3) {
        print_info_and_check_proof(&state, new_account_id, &register_email_0, index, key_type)
    }

    println!("User_1 infomation:");
    print_info_and_check_proof(&state, new_account_id, &register_email_1, 0, 0)
}

lazy_static::lazy_static! {
    pub static ref SLOT_0: U256 = ethabi::Uint::from(0 as i32);
    pub static ref SLOT_1: U256 = ethabi::Uint::from(2 as i32);
    pub static ref SLOT_2: U256 = ethabi::Uint::from(1 as i32);
    pub static ref U256_2: U256 = ethabi::Uint::from(2 as i32);
}

#[derive(Default)]
pub struct SmtKeyInfo {
    user_info_location: H256,        // store user_info
    keys_array_location: H256,       // store pubkey length
    keys_array_location_start: H256, // store fisrt pubkey
    key_type_location: H256,         // store key type
    pubkey_slot_location: H256,      // store pubkey slot
    pubkey_data_location: Vec<H256>, // store pubkey data
}

#[derive(Default)]
pub struct KeccakeKeyInfo {
    user_info_location: [u8; 32],        // store user_info
    keys_array_location: [u8; 32],       // store pubkey length
    keys_array_location_start: [u8; 32], // store fisrt pubkey
    key_type_location: [u8; 32],         // store key type
    pubkey_slot_location: [u8; 32],      // store pubkey slot
    pubkey_data_location: Vec<[u8; 32]>, // store pubkey data
}

impl KeccakeKeyInfo {
    fn to_smt_key_info(&self, id: u32) -> SmtKeyInfo {
        SmtKeyInfo {
            user_info_location: build_account_key(id, &self.user_info_location),
            keys_array_location: build_account_key(id, &self.keys_array_location),
            keys_array_location_start: build_account_key(id, &self.keys_array_location_start),
            key_type_location: build_account_key(id, &self.key_type_location),
            pubkey_slot_location: build_account_key(id, &self.pubkey_slot_location),
            pubkey_data_location: self
                .pubkey_data_location
                .iter()
                .map(|key| build_account_key(id, key))
                .collect(),
        }
    }
}

fn geneate_pubkey_storage_key(
    register_email: &[u8], // register_email, use as mapping key
    index: U256,           // the key index in keys array
) -> Result<KeccakeKeyInfo, &'static str> {
    let mut key_info = KeccakeKeyInfo::default();
    // keccak256(key | slot_0) to find userInfo location
    let user_info_location = tiny_keccak::keccak256(
        ethabi::encode(&[
            Token::FixedBytes(register_email.to_vec()),
            Token::Uint(*SLOT_0),
        ])
        .as_ref(),
    );
    key_info.user_info_location = user_info_location;

    // keccak256(key | slot_0) + slot_1 to find keys array location
    let mut keys_array_location = [0u8; 32];
    U256::from(user_info_location)
        .checked_add(*SLOT_1)
        .unwrap()
        .to_big_endian(&mut keys_array_location);
    key_info.keys_array_location = keys_array_location;

    // keccak256(keccak256(key | slot_0) + slot_0) to find keys array start
    let keys_array_location_start = tiny_keccak::keccak256(
        ethabi::encode(&[Token::FixedBytes(keys_array_location.to_vec())]).as_ref(),
    );
    key_info.keys_array_location_start = keys_array_location_start;

    // keccak256(keccak256(key | slot_0) + slot_0) + index * slot_count to find specific pubkey location
    let pubkey_location_number = U256::from(keys_array_location_start)
        .checked_add(index.checked_mul(*U256_2).unwrap())
        .unwrap();
    let mut key_type_location = [0u8; 32];
    pubkey_location_number.to_big_endian(&mut key_type_location);
    key_info.key_type_location = key_type_location;

    // keccak256(keccak256(key | slot_0) + slot_0) + index * slot_count + slot_2 to find specific keydata location
    let pubkey_data_slot_location_number = pubkey_location_number.checked_add(*SLOT_2).unwrap();
    let mut pubkey_data_slot_location = [0u8; 32];
    pubkey_data_slot_location_number.to_big_endian(&mut pubkey_data_slot_location);

    key_info.pubkey_slot_location = pubkey_data_slot_location;

    Ok(key_info)
}

fn geneate_pubkey_data_storage_key(
    register_email: &[u8], // register_email, use as mapping key
    index: U256,           // the key index in keys array
    key_type: u64,         // the key type(rsa k1 r1)
) -> Result<KeccakeKeyInfo, &'static str> {
    let mut key_info = geneate_pubkey_storage_key(register_email, index)?;
    let location = match key_type {
        0 => {
            // for rsa: key location should store 256(pubkey length)
            // pubkey store in
            // keccak256(keccak256(keccak256(key | slot_0) + slot_0) + index * slot_count)
            // ~ keccak256(keccak256(keccak256(key | slot_0) + slot_0) + index * slot_count) + 8
            let data_location_start = U256::from(tiny_keccak::keccak256(
                ethabi::encode(&[Token::FixedBytes(key_info.pubkey_slot_location.to_vec())])
                    .as_ref(),
            ));

            let mut res = vec![];
            for i in 0..8 as i32 {
                let mut key = [0u8; 32];
                data_location_start
                    .checked_add(U256::from(i))
                    .unwrap()
                    .to_big_endian(&mut key);

                res.push(key);
            }
            res
        }
        1 => {
            // for k1 key location store k1 pubkey and higher byte store 20byte pubkey
            let mut res = vec![];
            res.push(key_info.pubkey_slot_location);
            res
        }
        2 => {
            // for r1: key location should store 64(pubkey length)
            // pubkey store in
            // keccak256(keccak256(keccak256(key | slot_0) + slot_0) + index * slot_count)
            // ~ keccak256(keccak256(keccak256(key | slot_0) + slot_0) + index * slot_count) + 2
            let data_location_start = U256::from(tiny_keccak::keccak256(
                ethabi::encode(&[Token::FixedBytes(key_info.pubkey_slot_location.to_vec())])
                    .as_ref(),
            ));

            let mut res = vec![];
            for i in 0..2 as i32 {
                let mut key = [0u8; 32];
                data_location_start
                    .checked_add(U256::from(i))
                    .unwrap()
                    .to_big_endian(&mut key);

                res.push(key);
            }
            res
        }
        _ => {
            return Err("unknown key type");
        }
    };

    key_info.pubkey_data_location = location;

    Ok(key_info)
}

fn geneate_pubkey_smt_key(
    id: u32,               // account_id of entry storage contract
    register_email: &[u8], // register_email, use as mapping key
    index: U256,           // the key index in keys array
) -> Result<SmtKeyInfo, &'static str> {
    let key_info = geneate_pubkey_storage_key(register_email, index)?;
    Ok(key_info.to_smt_key_info(id))
}

fn geneate_pubkey_data_smt_key(
    id: u32,               // account_id of entry storage contract
    register_email: &[u8], // register_email, use as mapping key
    index: U256,           // the key index in keys array
    key_type: u64,         // the key type(rsa k1 r1)
) -> Result<SmtKeyInfo, &'static str> {
    let key_info = geneate_pubkey_data_storage_key(register_email, index, key_type)?;
    Ok(key_info.to_smt_key_info(id))
}

fn print_info_and_check_proof(
    state: &DummyState,
    id: u32,
    register_email: &[u8],
    index: i32,
    key_type: u64,
) {
    println!("Validate index {}, Key type {}", index, key_type);
    let smt_key_info = geneate_pubkey_data_smt_key(
        id,
        register_email,
        U256::from(index as i32),
        key_type as u64,
    )
    .unwrap();
    println!(
        "user_info_location: {}, value: {}",
        hex::encode(smt_key_info.user_info_location.as_slice()),
        hex::encode(
            state
                .tree
                .get(&smt_key_info.user_info_location)
                .unwrap()
                .as_slice()
        )
    );
    println!(
        "keys_array_location: {}, value: {}",
        hex::encode(smt_key_info.keys_array_location.as_slice()),
        hex::encode(
            state
                .tree
                .get(&smt_key_info.keys_array_location)
                .unwrap()
                .as_slice()
        )
    );
    println!(
        "keys_array_location_start: {}, value: {}",
        hex::encode(smt_key_info.keys_array_location_start.as_slice()),
        hex::encode(
            state
                .tree
                .get(&smt_key_info.keys_array_location_start)
                .unwrap()
                .as_slice()
        )
    );
    println!(
        "key_type_location: {}, value: {}",
        hex::encode(smt_key_info.key_type_location.as_slice()),
        hex::encode(
            state
                .tree
                .get(&smt_key_info.key_type_location)
                .unwrap()
                .as_slice()
        )
    );
    println!(
        "pubkey_slot_location: {}, value: {}",
        hex::encode(smt_key_info.pubkey_slot_location.as_slice()),
        hex::encode(
            state
                .tree
                .get(&smt_key_info.pubkey_slot_location)
                .unwrap()
                .as_slice()
        )
    );
    println!("Pubkey is:");
    let mut pubkey = vec![];
    let mut leaves = vec![];
    for smt_key in smt_key_info.pubkey_data_location.iter() {
        let value = state.tree.get(smt_key).unwrap();
        leaves.push((*smt_key, value));
        pubkey.extend_from_slice(value.as_slice());
    }

    println!("{}", hex::encode(&pubkey));

    let smt_proof = state
        .tree
        .merkle_proof(smt_key_info.pubkey_data_location)
        .unwrap();

    let smt_proof_compiled = smt_proof.clone().compile(leaves.clone()).unwrap();

    let verify_result = smt_proof
        .verify::<Blake2bHasher>(&state.calculate_root().unwrap(), leaves)
        .expect("verify");

    let smt_proof_bytes: Vec<u8> = smt_proof_compiled.into();

    println!(
        "verify result: {}, proof len:{}",
        verify_result,
        smt_proof_bytes.len()
    );
}

#[test]
fn test_unipass_key() {
    let key_0 =
        hex::decode("3630d4c879a209a5e41cb2c71b07d61aadaaa4309047307ba85d2a4f63e2bf70").unwrap();
    println!("Key_0: {:?}", key_0);
    let key_x =
        hex::decode("cbee61c757e46531c474caaf9577000ba2bf7ca9f01129398aa38a8c25dc32cf0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    println!("Key_x: {:?}", key_x);

    let test_key = hex::decode("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000").unwrap();

    let test_kec_key = tiny_keccak::keccak256(&test_key);
    println!("test key result: {}", hex::encode(test_kec_key));

    let slot = U256::from_str_radix("0", 10).unwrap();
    let concat_1 = ethabi::encode(&[Token::FixedBytes(key_0), Token::Uint(slot)]);

    println!("concat_1: {:?}, len:{}", concat_1, concat_1.len());
    let sol_key_1 = tiny_keccak::keccak256(&concat_1);
    println!(
        "sol_key 1: {}, len:{}",
        hex::encode(&sol_key_1),
        sol_key_1.len()
    );

    let sol_key_2 = tiny_keccak::keccak256(&sol_key_1);
    println!(
        "sol_key 2: {}, len:{}",
        hex::encode(&sol_key_2),
        sol_key_2.len()
    );

    for i in 0..10 {
        let smt_key = build_account_key(i, &sol_key_2);

        let smt_hex_key = hex::encode(smt_key.as_slice());

        if smt_hex_key == "fce57ab4ee20e990fcf736d0f17f110537ab9631f3933927bee65ee03d213aa0" {
            println!(
                "Got it!! account_id: {}, hex: {}",
                i,
                hex::encode(smt_key.as_slice())
            );
        } else {
            println!(
                "account_id: {}, smt_key : {}",
                i,
                hex::encode(smt_key.as_slice())
            );
        }
    }
}
