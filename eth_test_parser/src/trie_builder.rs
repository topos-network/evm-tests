//! Module responsible for converting deserialized json tests into
//! plonky2 generation inputs.
//!
//! In other words
//! ```ignore
//! crate::deserialize::TestBody -> plonky2_evm::generation::GenerationInputs
//! ```
use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use common::{
    config,
    types::{ConstGenerationInputs, Plonky2ParsedTest, TestVariant, TestVariantCommon}, revm::SerializableEVMInstance,
};
use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
};
use ethereum_types::{Address, H256, U256};
use hex_literal::hex;
use keccak_hash::keccak;
use plonky2_evm::{generation::{TrieInputs, mpt::{LegacyTransactionRlp, Type1TransactionRlp, Type2TransactionRlp}}, proof::BlockMetadata};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};

use crate::deserialize::{Env, GeneralStateTestBody, BlockchainTestBody, BlockHeader};

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

            let is_blockchain = 
                blockchain_test_body.blocks.len() > 0 &&
                blockchain_test_body.blocks[0].transactions.len() > 0 && // There are some tests with empty transactions field (e.g. eth_tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_send.jso)
                get_transaction_signature(&x.txbytes.0[..]) == (
                    blockchain_test_body.blocks[0].transactions[0].v,
                    blockchain_test_body.blocks[0].transactions[0].r,
                    blockchain_test_body.blocks[0].transactions[0].s,
                );
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
        println!("Biba cobreloa!");
        if blockchain_test_body.blocks.len() > 0 && blockchain_test_body.blocks[0].transactions.len() > 0 {
            println!("Firma 1: {:?}", (
                blockchain_test_body.blocks[0].transactions[0].v,
                blockchain_test_body.blocks[0].transactions[0].r,
                blockchain_test_body.blocks[0].transactions[0].s,
            ));
            println!("Las otras: {:?}", general_state_test_body
                .post
                .shanghai
                .iter()
                .map(|x| get_transaction_signature(&x.txbytes.0[..]))
                .collect::<Vec<_>>()
            );
        }
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

#[test]
fn test_signature() {
    let txbytes = hex!("f880806482520894d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0a1010000000000000000000000000000000000000000000000000000000000000001801ba0c16787a8e25e941d67691954642876c08f00996163ae7dfadbbfd6cd436f549da06180e5626cae31590f40641fe8f63734316c4bfeb4cdfab6714198c1044d2e28");
    print!("signature = {:?}", get_transaction_signature(&txbytes))
} 
