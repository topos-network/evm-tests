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
    types::{ConstGenerationInputs, Plonky2ParsedTest, TestVariant, TestVariantCommon}, revm::SerializableEVMInstance,
};
use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
};
use ethereum_types::{Address, H256, U256};
use keccak_hash::keccak;
use plonky2_evm::{generation::{TrieInputs, mpt::LegacyTransactionRlp}, proof::BlockMetadata};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use hex_literal::hex;

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

    let test_variants = general_state_test_body
        .post
        .shanghai
        .iter()
        .map(|x| {
            let txn: LegacyTransactionRlp = rlp::decode(&x.txbytes.0).expect(
                &format!("Couldn't decode transaction {:?}", x.txbytes.0)
            );
            let string = hex::encode(&x.txbytes.0);
            // Check if the signature of the current transaction coincides with the in the blockchain test
            let is_blockchain = blockchain_test_body.blocks[0].transactions.len() > 0 && // There are some tests with empty transactions field (e.g. eth_tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_send.jso)
                txn.r == blockchain_test_body.blocks[0].transactions[0].r &&
                txn.s == blockchain_test_body.blocks[0].transactions[0].s &&
                txn.v == blockchain_test_body.blocks[0].transactions[0].v;
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
