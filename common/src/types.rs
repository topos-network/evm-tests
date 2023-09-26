use std::{
    collections::HashMap,
    ops::RangeInclusive,
    str::{FromStr, Split},
};

use anyhow::{anyhow, Context};
use ethereum_types::{Address, H256, U256};
use plonky2_evm::proof::{BlockHashes, TrieRoots};
use plonky2_evm::{
    generation::{GenerationInputs, TrieInputs},
    proof::BlockMetadata,
};
use serde::{Deserialize, Serialize};

use crate::revm::SerializableEVMInstance;

#[derive(Debug, Deserialize, Serialize)]
pub struct ParsedTestManifest {
    pub plonky2_variants: Vec<Plonky2ParsedTest>,
    pub revm_variants: Option<Vec<SerializableEVMInstance>>,
}

pub struct FilteredVariantsOutput {
    pub variants: Vec<TestVariantRunInfo>,
    pub tot_variants_without_filter: usize,
}

impl ParsedTestManifest {
    pub fn into_filtered_variants(
        self,
        v_filter: Option<VariantFilterType>,
    ) -> FilteredVariantsOutput {
        // If `self.revm_variants` is None, the parser was unable to generate an `revm`
        // instance for any test variant. This occurs when some shared test data was
        // unable to be parsed (e.g. the `transaction` section). In this case, we
        // generate a `None` for each test variant slot so that it can be zipped with
        // plonky2 variants.
        let revm_variants: Vec<Option<SerializableEVMInstance>> = match self.revm_variants {
            // `revm_variants` will be parallel to `plonky2_variants`, given they are both
            // generated from the same vec (`test.post.merge`).
            None => (0..self.plonky2_variants.len()).map(|_| None).collect(),
            Some(v) => v.into_iter().map(Some).collect(),
        };

        let tot_variants_without_filter = self.plonky2_variants.len();

        let variants = self
            .plonky2_variants
            .into_iter()
            .zip(revm_variants.into_iter())
            .enumerate()
            .filter(|(variant_idx, _)| match &v_filter {
                Some(VariantFilterType::Single(v)) => variant_idx == v,
                Some(VariantFilterType::Range(r)) => r.contains(variant_idx),
                None => true,
            })
            .map(|(variant_idx, (t_var, revm_variant))| {
                let trie_roots_after = TrieRoots {
                    state_root: t_var.final_roots.state_root_hash,
                    transactions_root: t_var.final_roots.txn_trie_root_hash,
                    receipts_root: t_var.final_roots.receipts_trie_root_hash,
                };
                let gen_inputs = GenerationInputs {
                    signed_txns: vec![t_var.txn_bytes],
                    tries: t_var.plonky2_metadata.tries.clone(),
                    trie_roots_after,
                    genesis_state_trie_root: t_var.plonky2_metadata.genesis_state_root,
                    contract_code: t_var.plonky2_metadata.contract_code.clone(),
                    block_metadata: t_var.plonky2_metadata.block_metadata.clone(),
                    addresses: t_var.plonky2_metadata.addresses.clone(),
                    txn_number_before: U256::zero(),
                    gas_used_before: U256::zero(),
                    block_bloom_before: [U256::zero(); 8],
                    gas_used_after: t_var.plonky2_metadata.block_metadata.block_gas_used,
                    block_bloom_after: t_var.plonky2_metadata.block_metadata.block_bloom,
                    block_hashes: BlockHashes::default(),
                };

                TestVariantRunInfo {
                    gen_inputs,
                    final_roots: t_var.final_roots,
                    revm_variant,
                    variant_idx,
                }
            })
            .collect();

        FilteredVariantsOutput {
            variants,
            tot_variants_without_filter,
        }
    }
}

/// A parsed Ethereum test that is ready to be fed into `Plonky2`.
///
/// Note that for our runner we break any txn "variants" (see `indexes` under https://ethereum-tests.readthedocs.io/en/latest/test_types/gstate_tests.html#post-section) into separate sub-tests when running. This is because we don't want a single sub-test variant to cause the entire test to fail (we just want the variant to fail).
#[derive(Debug, Deserialize, Serialize)]
pub struct Plonky2ParsedTest {
    pub txn_bytes: Vec<u8>,
    pub final_roots: ExpectedFinalRoots,

    /// All the metadata needed to prove the transaction in the `test_variant`.
    pub plonky2_metadata: TestMetadata,
}

#[derive(Debug)]
pub struct TestVariantRunInfo {
    pub gen_inputs: GenerationInputs,
    pub final_roots: ExpectedFinalRoots,
    pub revm_variant: Option<SerializableEVMInstance>,
    pub variant_idx: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExpectedFinalRoots {
    /// The root hash of the expected final state trie.
    pub state_root_hash: H256,
    /// The root hash of the expected final transactions trie.
    pub txn_trie_root_hash: H256,
    /// The root hash of the expected final receipts trie.
    pub receipts_trie_root_hash: H256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestMetadata {
    pub tries: TrieInputs,
    pub genesis_state_root: H256,
    pub contract_code: HashMap<H256, Vec<u8>>,
    pub block_metadata: BlockMetadata,
    pub addresses: Vec<Address>,
}

#[derive(Clone, Debug)]
pub enum VariantFilterType {
    Single(usize),
    Range(RangeInclusive<usize>),
}

impl FromStr for VariantFilterType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_intern(s)
            .with_context(|| {
                format!(
                    "Expected a single value or a range, but instead got \"{}\".",
                    s
                )
            })
            .map_err(|e| format!("{e:#}"))
    }
}

impl VariantFilterType {
    fn from_str_intern(s: &str) -> anyhow::Result<Self> {
        // Did we get passed a single value?
        if let Ok(v) = s.parse::<usize>() {
            return Ok(Self::Single(v));
        }

        // Check if it's a range.
        let mut range_vals = s.split("..=");

        let start = Self::next_and_try_parse(&mut range_vals)?;
        let end = Self::next_and_try_parse(&mut range_vals)?;

        if range_vals.count() > 0 {
            return Err(anyhow!(
                "Parsed a range but there were unexpected characters afterwards!"
            ));
        }

        Ok(Self::Range(start..=end))
    }

    fn next_and_try_parse(range_vals: &mut Split<&str>) -> anyhow::Result<usize> {
        let unparsed_val = range_vals
            .next()
            .with_context(|| "Parsing a value as a `RangeInclusive`")?;
        let res = unparsed_val
            .parse()
            .with_context(|| format!("Parsing the range val \"{unparsed_val}\" into a usize"))?;

        Ok(res)
    }
}
