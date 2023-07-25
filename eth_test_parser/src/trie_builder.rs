//! Module responsible for converting deserialized json tests into
//! plonky2 generation inputs.
//!
//! In other words
//! ```ignore
//! crate::deserialize::TestBody -> plonky2_evm::generation::GenerationInputs
//! ```
use std::collections::HashMap;

use anyhow::Result;
use common::{
    config,
    types::{ConstGenerationInputs, Plonky2ParsedTest, TestVariant, TestVariantCommon},
};
use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
};
use ethereum_types::{Address, H256, U256};
use keccak_hash::keccak;
use plonky2_evm::{generation::{TrieInputs, mpt::{LegacyTransactionRlp, Type1TransactionRlp, Type2TransactionRlp}}, proof::BlockMetadata};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};

use crate::deserialize::{Env, GeneralStateTestBody, BlockchainTestBody};

#[derive(RlpDecodable, RlpEncodable)]
pub(crate) struct AccountRlp {
    nonce: u64,
    balance: U256,
    storage_hash: H256,
    code_hash: H256,
}

impl Env {
    fn block_metadata(&self, block_bloom: [U256; 8], block_gas_used: U256) -> BlockMetadata {
        BlockMetadata {
            block_beneficiary: self.current_coinbase,
            block_timestamp: self.current_timestamp,
            block_number: self.current_number,
            block_difficulty: self.current_difficulty,
            block_gaslimit: self.current_gas_limit,
            block_chain_id: config::ETHEREUM_CHAIN_ID.into(),
            block_base_fee: self.current_base_fee,
            block_bloom,
            block_gas_used
        }
    }
}

impl GeneralStateTestBody {
    fn get_storage_tries(&self) -> Vec<(H256, HashedPartialTrie)> {
        self.pre
            .iter()
            .map(|(acc_key, pre_acc)| {
                let storage_trie = pre_acc
                    .storage
                    .iter()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(k, v)| {
                        (
                            Nibbles::from_h256_be(hash(&u256_to_be_bytes(*k))),
                            v.rlp_bytes().to_vec(),
                        )
                    })
                    .collect();

                (hash(acc_key.as_bytes()), storage_trie)
            })
            .collect()
    }

    fn get_state_trie(&self, storage_tries: &[(H256, HashedPartialTrie)]) -> HashedPartialTrie {
        self.pre
            .iter()
            .map(|(acc_key, pre_acc)| {
                let addr_hash = hash(acc_key.as_bytes());
                let code_hash = hash(&pre_acc.code.0);
                let storage_hash = get_storage_hash(&addr_hash, storage_tries);

                let rlp = AccountRlp {
                    nonce: pre_acc.nonce,
                    balance: pre_acc.balance,
                    storage_hash,
                    code_hash,
                }
                .rlp_bytes();

                (Nibbles::from_h256_be(addr_hash), rlp.to_vec())
            })
            .collect()
    }

    #[allow(unused)] // TODO: Will be used later.
    fn get_txn_trie(&self) -> HashedPartialTrie {
        self.post
            .shanghai
            .iter()
            .enumerate()
            .map(|(txn_idx, post)| {
                (
                    Nibbles::from_bytes_be(&txn_idx.to_be_bytes()).unwrap(), //TODO: It seems this should be rlp(txn_idx)
                    post.txbytes.0.clone(),
                )
            })
            .collect()
    }
}

fn get_storage_hash(
    hashed_account_address: &H256,
    storage_tries: &[(H256, HashedPartialTrie)],
) -> H256 {
    storage_tries
        .iter()
        .find(|(addr, _)| hashed_account_address == addr)
        .unwrap()
        .1
        .hash()
}

fn u256_to_be_bytes(x: U256) -> [u8; 32] {
    let mut bytes = [0; 32];
    x.to_big_endian(&mut bytes);
    bytes
}

fn hash(bytes: &[u8]) -> H256 {
    H256::from(keccak(bytes).0)
}

pub(crate) fn as_plonky2_test_input(general_state_test_body: &GeneralStateTestBody, blockchain_test_body: &BlockchainTestBody) -> Plonky2ParsedTest {
    let storage_tries = general_state_test_body.get_storage_tries();
    let state_trie = general_state_test_body.get_state_trie(&storage_tries);

    let tries = TrieInputs {
        state_trie,
        transactions_trie: HashedPartialTrie::default(), // TODO: Is it ok to start with the empty trie?
        receipts_trie: HashedPartialTrie::default(), /* TODO: Fill in once we know what we
                                                        * are
                                                        * doing... */
        storage_tries,
    };

    let contract_code: HashMap<_, _> = general_state_test_body
        .pre
        .values()
        .map(|pre| (hash(&pre.code.0), pre.code.0.clone()))
        .collect();

    let test_variants: Vec<_> = general_state_test_body
        .post
        .shanghai
        .iter()
        .map(|x| {
            // Check if the signature of the current transaction coincides with the one in the blockchain test
            let is_blockchain = if blockchain_test_body.blocks[0].transactions.len() > 0 {
                get_transaction_signature(&x.txbytes.0[..]) == (
                    blockchain_test_body.blocks[0].transactions[0].v,
                    blockchain_test_body.blocks[0].transactions[0].r,
                    blockchain_test_body.blocks[0].transactions[0].s,
                )
            }
            else { // We enter this branch if the test is supposed to fail
                blockchain_test_body.blocks[0].transaction_sequence[0].raw_bytes.0 == x.txbytes.0
            };
            TestVariant {
                txn_bytes: x.txbytes.0.clone(),
                is_blockchain,
                common: TestVariantCommon {
                    expected_final_account_state_root_hash: x.hash,
                    // TODO: transaction trie shouldn't change with variants?
                    expected_final_transactions_root_hash: blockchain_test_body.blocks[0].block_header.transactions_trie,
                    expected_final_receipt_root_hash: blockchain_test_body.blocks[0].block_header.receipt_trie
                },
            }
        })
        .collect();
    let is_blockchain = test_variants
        .iter()
        .fold(false, |acc, x| acc||x.is_blockchain);
    // the blockchain tests wihtout variant but with non empty blocks an txns
    if !is_blockchain {
        println!(
            "Los tries {:?} and {:?}",
            blockchain_test_body.blocks[0].block_header.transactions_trie,
            blockchain_test_body.blocks[0].block_header.transactions_trie,
        )
    }

    let (_ctr, sera_una_de_esas_blockchains) = test_variants
        .iter()
        .fold((0, false), |(ctr, acc), x| (ctr+1, acc || x.is_blockchain));
    if !sera_una_de_esas_blockchains && blockchain_test_body.blocks.len() > 0 && blockchain_test_body.blocks[0].transactions.len() > 0 {
            println!("una de las firmas {:?}", test_variants[0].txn_bytes);
            println!("la de la bc = {:?}", (
                blockchain_test_body.blocks[0].transactions[0].v,
                blockchain_test_body.blocks[0].transactions[0].r,
                blockchain_test_body.blocks[0].transactions[0].s
            ));
    }

    let addresses = general_state_test_body.pre.keys().copied().collect::<Vec<Address>>();

    let const_plonky2_inputs = ConstGenerationInputs {
        tries,
        contract_code,
        block_metadata: general_state_test_body.env.block_metadata(
            blockchain_test_body.blocks[0].block_header.bloom,
            blockchain_test_body.blocks[0].block_header.gas_used
        ),
        addresses,
        gas_used_before: blockchain_test_body.genesis_block_header.gas_used,
        block_bloom_before: blockchain_test_body.genesis_block_header.bloom
    };

    Plonky2ParsedTest {
        test_variants,
        const_plonky2_inputs,
    }
}

/// Decodes the bytes of the transaction an returns the transaction signature
fn get_transaction_signature(txbytes: &[u8]) -> (U256, U256, U256) {
    // A type 1 txn starts with 0x01
    if txbytes[0] == 1u8 {
        let txn: Type1TransactionRlp = rlp::decode(&txbytes[1..]).expect("Invalid type 1 or 2 txn");
        return (txn.y_parity, txn.r, txn.s);
    }
    // A type 2 txn starts with 0x02
    else if  txbytes[0] == 2u8 {
        let txn: Type2TransactionRlp = rlp::decode(&txbytes[1..]).expect("Invalid type 1 or 2 txn");
        return (txn.y_parity, txn.r, txn.s)
    }
    else {
        let txn: LegacyTransactionRlp = rlp::decode(&txbytes)
            .expect(&format!("Couldn't decode transaction {:?}", txbytes));
        return (txn.v, txn.r, txn.s)
    }
}

use bytes::Bytes;
use hex_literal::hex;
#[test]
fn test_signature() {
    let txbytes = hex!("f880806482520894d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0a1010000000000000000000000000000000000000000000000000000000000000001801ba0c16787a8e25e941d67691954642876c08f00996163ae7dfadbbfd6cd436f549da06180e5626cae31590f40641fe8f63734316c4bfeb4cdfab6714198c1044d2e28");
    print!("signature = {:?}", get_transaction_signature(&txbytes))
} 

#[test]
fn de_rlp_smthng() {
    use rlp::Rlp;
    let enc_rlp = hex!("f90261f901f9a0772baf505023559d6b8a3b6e29fceb1dad4c1776091a54c797e23bdaf27f1313a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa000c7c25199d1252abf9df34035b5e2bb5577d255e0b108f175a0581573e537baa0a02cfaaef253dee0e8c7e6cfcc1960f4566d266cf1081772f1446d2109838efba095904f4e949bbc1f767e77a7f53dd981613a4c2d23ee353ae26fcd58f1ac87aeb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083020000018401c9c3808303fa5d8203e800a00000000000000000000000000000000000000000000000000000000000000000880000000000000000f862f860800a832dc6c094100000000000000000000000000000000000000080801ba07763c200d265ba0050627c8c7b4c19bf118b3581a3de22dbcebdfcb6e8565790a0514908f638ddc4b1402230e34692f43bb92713ff2cad3627814cf6fb19ac2e43c0");
    let dec_rlp = Rlp::new(&enc_rlp);
    //println!("purported state root = {:?}", dec_rlp.at(3).unwrap().as_val::<H256>());
    // print_rlp(dec_rlp, "");
    println!("list size = {}", dec_rlp.item_count().unwrap());
    println!("bloom = {:?}", dec_rlp.at(0).unwrap().at(6).unwrap().as_val::<String>());
    println!("gas limit = {:?}", dec_rlp.at(0).unwrap().at(9).unwrap().as_val::<U256>());
    println!("gas used = {:?}", dec_rlp.at(0).unwrap().at(10).unwrap().as_val::<U256>());
    println!("stat hash = {:?}", dec_rlp.at(0).unwrap().at(3).unwrap().as_val::<H256>());
    println!("txn hash = {:?}", dec_rlp.at(0).unwrap().at(4).unwrap().as_val::<H256>());
    println!("receipt hash = {:?}", dec_rlp.at(0).unwrap().at(5).unwrap().as_val::<H256>());

    for i in 0..dec_rlp.item_count().unwrap() {
        let item = dec_rlp.at(i).unwrap();
        let item_count = item.item_count().unwrap();
        println!("item {} item_count() = {}", i, item_count);
        if item_count > 0 {
            for i in 1..item_count {
                println!("\tcontent {} = {:?}", i, item.at(i))
            }
        }
        else {
            println!("\t item {} content = {:?}", i, item);
        }
    }
}

fn print_rlp(item: rlp::Rlp, tab: &str) {
    println!("{} contents:", tab);
    if !item.is_list() {
        println!("{}\t item = {:?}", tab, item);
    }
    else {
        let item_count = item.item_count().unwrap();
        for i in 0..item_count {
            print!("{}\t item = ", tab);
            print_rlp(item.at(i).unwrap(), &format!("{}\t", tab).as_str())
        }
    }
}