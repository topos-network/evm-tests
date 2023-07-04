#![allow(dead_code)]
use std::{marker::PhantomData, fmt};
use std::collections::HashMap;
use std::str::FromStr;
use anyhow::Result;

use common::{types::Plonky2ParsedTest, revm::SerializableEVMInstance};
use ethereum_types::{Address, H160, H256, U256, U512};
use hex::FromHex;
use serde::de::MapAccess;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};
use serde_with::{serde_as, with_prefix, DefaultOnNull, NoneAsEmptyString};

/// In a couple tests, an entry in the `transaction.value` key will contain
/// the prefix, `0x:bigint`, in addition to containing a value greater than 256
/// bits. This breaks U256 deserialization in two ways:
/// 1. The `0x:bigint` prefix breaks string parsing.
/// 2. The value will be greater than 256 bits.
///
/// This helper takes care of stripping that prefix, if it exists, and
/// additionally pads the value with a U512 to catch overflow. Note that this
/// implementation is specific to a Vec<_>; in the event that this syntax is
/// found to occur more often than this particular instance
/// (`transaction.value`), this logic should be broken out to be modular.
///
/// See [this test](https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stTransactionTest/ValueOverflow.json#L197) for a concrete example.
fn vec_eth_big_int_u512<'de, D>(deserializer: D) -> Result<Vec<U512>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<String> = Deserialize::deserialize(deserializer)?;
    const BIG_INT_PREFIX: &str = "0x:bigint ";

    s.into_iter()
        .map(|s| {
            U512::from_str(s.strip_prefix(BIG_INT_PREFIX).unwrap_or(&s)).map_err(D::Error::custom)
        })
        .collect()
}

#[derive(Clone, Deserialize, Debug)]
// "self" just points to this module.
pub(crate) struct ByteString(#[serde(with = "self")] pub(crate) Vec<u8>);

// Gross, but there is no Serde crate that can both parse a hex string with a
// prefix and also deserialize from a `Vec<u8>`.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct PrefixHexStrVisitor();

    impl<'de> Visitor<'de> for PrefixHexStrVisitor {
        type Value = Vec<u8>;

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            FromHex::from_hex(Self::remove_prefix(data)).map_err(Error::custom)
        }

        fn visit_borrowed_str<E>(self, data: &'de str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            FromHex::from_hex(Self::remove_prefix(data)).map_err(Error::custom)
        }

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a hex encoded string with a prefix")
        }
    }

    impl PrefixHexStrVisitor {
        fn remove_prefix(data: &str) -> &str {
            &data[2..]
        }
    }

    deserializer.deserialize_string(PrefixHexStrVisitor())
}

fn u64_from_hex<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    u64::from_str_radix(&s[2..], 16).map_err(D::Error::custom)
}

fn vec_u64_from_hex<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<String> = Deserialize::deserialize(deserializer)?;
    s.into_iter()
        .map(|x| u64::from_str_radix(&x[2..], 16).map_err(D::Error::custom))
        .collect::<Result<Vec<_>, D::Error>>()
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Env {
    pub(crate) current_base_fee: U256,
    pub(crate) current_coinbase: H160,
    pub(crate) current_difficulty: U256,
    pub(crate) current_gas_limit: U256,
    pub(crate) current_number: U256,
    pub(crate) current_random: U256,
    pub(crate) current_timestamp: U256,
    pub(crate) previous_hash: H256,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PostStateIndexes {
    pub(crate) data: usize,
    pub(crate) gas: usize,
    pub(crate) value: usize,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PostState {
    pub(crate) hash: H256,
    pub(crate) indexes: PostStateIndexes,
    pub(crate) logs: H256,
    pub(crate) txbytes: ByteString,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Post {
    pub(crate) shanghai: Vec<PostState>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PreAccount {
    pub(crate) balance: U256,
    pub(crate) code: ByteString,
    #[serde(deserialize_with = "u64_from_hex")]
    pub(crate) nonce: u64,
    pub(crate) storage: HashMap<U256, U256>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessList {
    pub(crate) address: Address,
    #[serde(default)]
    pub(crate) storage_keys: Vec<U256>,
}

#[serde_as]
#[derive(Deserialize, Debug)]
/// This is a wrapper around a `Vec<AccessList>` that is used to deserialize a
/// `null` into an empty vec.
pub(crate) struct AccessListsInner(
    #[serde_as(deserialize_as = "DefaultOnNull")] pub(crate) Vec<AccessList>,
);

#[serde_as]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransactionGeneralState {
    #[serde(default)]
    pub(crate) access_lists: Vec<AccessListsInner>,
    pub(crate) data: Vec<ByteString>,
    #[serde(deserialize_with = "vec_u64_from_hex")]
    pub(crate) gas_limit: Vec<u64>,
    pub(crate) gas_price: Option<U256>,
    pub(crate) nonce: U256,
    #[serde(default)]
    pub(crate) secret_key: H256,
    pub(crate) sender: H160,
    #[serde_as(as = "NoneAsEmptyString")]
    pub(crate) to: Option<H160>,
    // Protect against overflow.
    #[serde(deserialize_with = "vec_eth_big_int_u512")]
    pub(crate) value: Vec<U512>,
}

#[serde_as]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransactionBlockchainTest {
    #[serde(default)]
    pub(crate) access_lists: Vec<AccessListsInner>,
    pub(crate) data: ByteString,
    pub(crate) gas_limit: U256,
    pub(crate) gas_price: Option<U256>,
    pub(crate) nonce: U256,
    #[serde(default)]
    pub(crate) secret_key: H256,
    pub(crate) sender: H160,
    #[serde_as(as = "NoneAsEmptyString")]
    pub(crate) to: Option<H160>,
    // Protect against overflow.
    pub(crate) value: U512,
}

#[derive(Deserialize, Debug)]
pub(crate) struct GeneralStateTestBody {
    pub(crate) env: Env,
    pub(crate) post: Post,
    pub(crate) transaction: TransactionGeneralState,
    pub(crate) pre: HashMap<H160, PreAccount>,
}

/*
    Strucs for deserializing tests in the BlockchainTest folder
 */

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BlockHeader {
    bloom: ByteString,
    coinbase: U256,
    difficulty: U256,
    extra_data: ByteString,
    gas_limit: U256,
    gas_used: U256,
    hash: H256,
    mix_hash: H256,
    nonce: U256,
    number: U256,
    parent_hash: H256,
    receipt_trie: H256,
    state_root: H256,
    timestamp: U256,
    transactions_trie: H256,
    uncle_hash: H256
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Block {
    block_header: BlockHeader,
    rlp: ByteString,
    transactions: Vec<TransactionBlockchainTest>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BlockchainTestBody {
    blocks: Vec<Block>,
    genesis_block_header: BlockHeader,
    genesis_r_l_p: ByteString, // How to make it genesis_rlp?,
    lastblockhash: H256,
    post_state: HashMap<H160, PreAccount>, // TODO: Doesn't seem correct
    pre: HashMap<H160, PreAccount>,
}

// TODO: I wanted to make this a trie, but I run into problems becasue at some point I need to implement impl<T> From<T> for
// Plonky2ParsedTest, where T: TestBody, and the compiler complains that:
// error: type parameter `T` must be used as the type parameter for some local type (e.g. `MyStruct<T>`);
// only traits defined in the current crate can be implemented for a type parameter  
#[derive(Debug)]
pub(crate) enum TestBody {
    BlockchainTestBody(BlockchainTestBody),
    GeneralStateTestBody(GeneralStateTestBody)
}

impl TestBody {
    pub(crate) fn as_plonky2_test_input(&self) -> Plonky2ParsedTest {
        match self {
            Self::BlockchainTestBody(blockchain_test) => blockchain_test.as_plonky2_test_input(),
            Self::GeneralStateTestBody(general_state_test) => general_state_test.as_plonky2_test_input()
        }
    }
    pub(crate) fn as_serializable_evm_instances(&self) -> Result<Vec<SerializableEVMInstance>, > {
        match self {
            Self::BlockchainTestBody(blockchain_test) => blockchain_test.as_serializable_evm_instances(),
            Self::GeneralStateTestBody(general_state_test) => general_state_test.as_serializable_evm_instances()
        }
    }
}

struct TestBodyVisitor {
    marker: PhantomData<fn() -> TestBody>
}

impl TestBodyVisitor {
    fn new() -> Self {
        TestBodyVisitor {
            marker: PhantomData
        }
    }
}

impl<'de> Visitor<'de> for TestBodyVisitor {
    type Value = TestBody;

    // Format a message stating what data this Visitor expects to receive.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a valid GeneralState or Blockchain test body")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>
    {
        while let Some((key, body)) = access.next_entry::<String, _>()? {
            if key.ends_with("_Shanghai") {
                let body: BlockchainTestBody = serde_json::from_value(body).expect("Invalid Blockchain test");
                return Ok(TestBody::BlockchainTestBody(body))
            }
            else if let Ok(body) = serde_json::from_value::<GeneralStateTestBody>(body) {
                return Ok(TestBody::GeneralStateTestBody(body))
            }
        }
        Err(serde::de::Error::custom("Invalid JSON"))
    }
}

impl<'de> Deserialize<'de> for TestBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(TestBodyVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::{U256, H256};
    use hex_literal::hex;
    use super::{ByteString, TestBody, Block};

    const TEST_HEX_STR: &str = "\"0xf863800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0ffb600e63115a7362e7811894a91d8ba4330e526f22121c994c4692035dfdfd5a06198379fcac8de3dbfac48b165df4bf88e2088f294b61efb9a65fe2281c76e16\"";

    const GENERALSTATE_TEST_JSON: &str = "
    {
        \"delegatecallAfterTransition\" : {
            \"_info\" : {
                \"comment\" : \"\",
                \"filling-rpc-server\" : \"evm version 1.11.4-unstable-e14043db-20230308\",
                \"filling-tool-version\" : \"retesteth-0.3.0-shanghai+commit.fd2c0a83.Linux.g++\",
                \"generatedTestHash\" : \"944605854dec4f6ea6b54205ebad969d1abf831d999a2eb15df5e80800992aaa\",
                \"lllcversion\" : \"Version: 0.5.14-develop.2022.7.30+commit.a096d7a9.Linux.g++\",
                \"solidity\" : \"Version: 0.8.17+commit.8df45f5f.Linux.g++\",
                \"source\" : \"src/GeneralStateTestsFiller/stTransitionTest/delegatecallAfterTransitionFiller.json\",
                \"sourceHash\" : \"a996db02ecee83073b7910341d26a0e227296a3d2ba14ba840cbac6078eb500c\"
            },
            \"env\" : {
                \"currentBaseFee\" : \"0x0a\",
                \"currentCoinbase\" : \"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba\",
                \"currentDifficulty\" : \"0x020000\",
                \"currentGasLimit\" : \"0x01c9c380\",
                \"currentNumber\" : \"0x118c31\",
                \"currentRandom\" : \"0x0000000000000000000000000000000000000000000000000000000000020000\",
                \"currentTimestamp\" : \"0x03e8\",
                \"previousHash\" : \"0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6\"
            },
            \"post\" : {
                \"Berlin\" : [
                    {
                        \"hash\" : \"0x9f429cdd014c90fce9d5e79004f954955855cd3726e806ae954e566a8696a95a\",
                        \"indexes\" : {
                            \"data\" : 0,
                            \"gas\" : 0,
                            \"value\" : 0
                        },
                        \"logs\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                        \"txbytes\" : \"0xf860800a832dc6c094095e7baea6a6c7c4c2dfeb977efac326af552d8780801ca096fe0bdc8ea5e06836f0a4bdebad21024a56b36549e00aeae0d3d5e8c6f32302a021b8b5010ea4464453625562c4c0f0ec3039d1ed042db1e5cf02fb9e33d0b8d5\"
                    }
                ],
                \"Istanbul\" : [
                    {
                        \"hash\" : \"0xf60425143da7bd8a0fb92740fab016eb86b4e02051d6852befc5e26fd48ce742\",
                        \"indexes\" : {
                            \"data\" : 0,
                            \"gas\" : 0,
                            \"value\" : 0
                        },
                        \"logs\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                        \"txbytes\" : \"0xf860800a832dc6c094095e7baea6a6c7c4c2dfeb977efac326af552d8780801ca096fe0bdc8ea5e06836f0a4bdebad21024a56b36549e00aeae0d3d5e8c6f32302a021b8b5010ea4464453625562c4c0f0ec3039d1ed042db1e5cf02fb9e33d0b8d5\"
                    }
                ],
                \"London\" : [
                    {
                        \"hash\" : \"0x82839135ead533b540a4894ed296a14f5ff764e53a10d6ab15e12941d8adeb91\",
                        \"indexes\" : {
                            \"data\" : 0,
                            \"gas\" : 0,
                            \"value\" : 0
                        },
                        \"logs\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                        \"txbytes\" : \"0xf860800a832dc6c094095e7baea6a6c7c4c2dfeb977efac326af552d8780801ca096fe0bdc8ea5e06836f0a4bdebad21024a56b36549e00aeae0d3d5e8c6f32302a021b8b5010ea4464453625562c4c0f0ec3039d1ed042db1e5cf02fb9e33d0b8d5\"
                    }
                ],
                \"Merge\" : [
                    {
                        \"hash\" : \"0x82839135ead533b540a4894ed296a14f5ff764e53a10d6ab15e12941d8adeb91\",
                        \"indexes\" : {
                            \"data\" : 0,
                            \"gas\" : 0,
                            \"value\" : 0
                        },
                        \"logs\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                        \"txbytes\" : \"0xf860800a832dc6c094095e7baea6a6c7c4c2dfeb977efac326af552d8780801ca096fe0bdc8ea5e06836f0a4bdebad21024a56b36549e00aeae0d3d5e8c6f32302a021b8b5010ea4464453625562c4c0f0ec3039d1ed042db1e5cf02fb9e33d0b8d5\"
                    }
                ],
                \"Shanghai\" : [
                    {
                        \"hash\" : \"0x82839135ead533b540a4894ed296a14f5ff764e53a10d6ab15e12941d8adeb91\",
                        \"indexes\" : {
                            \"data\" : 0,
                            \"gas\" : 0,
                            \"value\" : 0
                        },
                        \"logs\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                        \"txbytes\" : \"0xf860800a832dc6c094095e7baea6a6c7c4c2dfeb977efac326af552d8780801ca096fe0bdc8ea5e06836f0a4bdebad21024a56b36549e00aeae0d3d5e8c6f32302a021b8b5010ea4464453625562c4c0f0ec3039d1ed042db1e5cf02fb9e33d0b8d5\"
                    }
                ]
            },
            \"pre\" : {
                \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\" : {
                    \"balance\" : \"0x0de0b6b3a7640000\",
                    \"code\" : \"0x600260006040600073945304eb96065b2a98b57a48a06ae28d285a71b56207a120f460005500\",
                    \"nonce\" : \"0x00\",
                    \"storage\" : {
                    }
                },
                \"0x945304eb96065b2a98b57a48a06ae28d285a71b5\" : {
                    \"balance\" : \"0x17\",
                    \"code\" : \"0x336001553460025500\",
                    \"nonce\" : \"0x00\",
                    \"storage\" : {
                    }
                },
                \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\" : {
                    \"balance\" : \"0x0de0b6b3a7640000\",
                    \"code\" : \"0x\",
                    \"nonce\" : \"0x00\",
                    \"storage\" : {
                    }
                }
            },
            \"transaction\" : {
                \"data\" : [
                    \"0x\"
                ],
                \"gasLimit\" : [
                    \"0x2dc6c0\"
                ],
                \"gasPrice\" : \"0x0a\",
                \"nonce\" : \"0x00\",
                \"secretKey\" : \"0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8\",
                \"sender\" : \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\",
                \"to\" : \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\",
                \"value\" : [
                    \"0x00\"
                ]
            }
        }
    }
    ";
    const BLOCKCHAIN_TEST_JSON: &str = "
    {\"addmodNonConst_d0g0v1_Shanghai\" : {
        \"_info\" : {
            \"comment\" : \"\",
            \"filling-rpc-server\" : \"evm version 1.11.4-unstable-e14043db-20230308\",
            \"filling-tool-version\" : \"retesteth-0.3.0-shanghai+commit.fd2c0a83.Linux.g++\",
            \"generatedTestHash\" : \"c48207bf96c93f2f6060506ca930ec33a826347c6a23103a17f75ca0be6bd3b3\",
            \"lllcversion\" : \"Version: 0.5.14-develop.2022.7.30+commit.a096d7a9.Linux.g++\",
            \"solidity\" : \"Version: 0.8.17+commit.8df45f5f.Linux.g++\",
            \"source\" : \"src/GeneralStateTestsFiller/stArgsZeroOneBalance/addmodNonConstFiller.yml\",
            \"sourceHash\" : \"42a505af9a6787365d2a62bc3e3c81c7b8d2bc840edcbc59c939251cc96973e0\"
        },
        \"blocks\" : [
            {
                \"blockHeader\" : {
                    \"baseFeePerGas\" : \"0x0a\",
                    \"bloom\" : \"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",
                    \"coinbase\" : \"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba\",
                    \"difficulty\" : \"0x00\",
                    \"extraData\" : \"0x00\",
                    \"gasLimit\" : \"0x0f4240\",
                    \"gasUsed\" : \"0x5be0\",
                    \"hash\" : \"0xea6ffca9824f1c6d6d388cd891c9431c98c0884ba4c1568eb878824d285cd925\",
                    \"mixHash\" : \"0x0000000000000000000000000000000000000000000000000000000000020000\",
                    \"nonce\" : \"0x0000000000000000\",
                    \"number\" : \"0x01\",
                    \"parentHash\" : \"0xdfe68772278a06751a59057d9a77665b7fd088bbf40afb9a8ad2669fc8f0a872\",
                    \"receiptTrie\" : \"0x49f388a0891339e0aa9e240338a3394f74fef2088039c1fb2e0e1f731e3eb390\",
                    \"stateRoot\" : \"0x06cae8a39ec7d89dff0f76c53fa1ea0cfb58254a6ab3696baa4dcf5b38822707\",
                    \"timestamp\" : \"0x03e8\",
                    \"transactionsTrie\" : \"0x174ccc4f3050aca8eb96ee492d7f77c48698de3988b3a422e2bc6974348182c0\",
                    \"uncleHash\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                    \"withdrawalsRoot\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"
                },
                \"rlp\" : \"0xf9027ff90216a0dfe68772278a06751a59057d9a77665b7fd088bbf40afb9a8ad2669fc8f0a872a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa006cae8a39ec7d89dff0f76c53fa1ea0cfb58254a6ab3696baa4dcf5b38822707a0174ccc4f3050aca8eb96ee492d7f77c48698de3988b3a422e2bc6974348182c0a049f388a0891339e0aa9e240338a3394f74fef2088039c1fb2e0e1f731e3eb390b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008001830f4240825be08203e800a000000000000000000000000000000000000000000000000000000000000200008800000000000000000aa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421f862f860800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d8701801ca09d46b87169053cc40670aef750b032c895cde3e35c2c7f5a37c059272e0914c7a04d4a94b67b2776cc3e0fca2ed9503c10fd92ec79f1b2dcbb85df9634c7de3119c0c0\",
                \"transactions\" : [
                    {
                        \"data\" : \"0x\",
                        \"gasLimit\" : \"0x061a80\",
                        \"gasPrice\" : \"0x0a\",
                        \"nonce\" : \"0x00\",
                        \"r\" : \"0x9d46b87169053cc40670aef750b032c895cde3e35c2c7f5a37c059272e0914c7\",
                        \"s\" : \"0x4d4a94b67b2776cc3e0fca2ed9503c10fd92ec79f1b2dcbb85df9634c7de3119\",
                        \"sender\" : \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\",
                        \"to\" : \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\",
                        \"v\" : \"0x1c\",
                        \"value\" : \"0x01\"
                    }
                ],
                \"uncleHeaders\" : [
                ],
                \"withdrawals\" : [
                ]
            }
        ],
        \"genesisBlockHeader\" : {
            \"baseFeePerGas\" : \"0x0b\",
            \"bloom\" : \"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",
            \"coinbase\" : \"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba\",
            \"difficulty\" : \"0x00\",
            \"extraData\" : \"0x00\",
            \"gasLimit\" : \"0x0f4240\",
            \"gasUsed\" : \"0x00\",
            \"hash\" : \"0xdfe68772278a06751a59057d9a77665b7fd088bbf40afb9a8ad2669fc8f0a872\",
            \"mixHash\" : \"0x0000000000000000000000000000000000000000000000000000000000020000\",
            \"nonce\" : \"0x0000000000000000\",
            \"number\" : \"0x00\",
            \"parentHash\" : \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"receiptTrie\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",
            \"stateRoot\" : \"0x9f91e48451b763f8f7a3388d1748f55e3251e31fcb3f06af8969c125432e93ab\",
            \"timestamp\" : \"0x00\",
            \"transactionsTrie\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",
            \"uncleHash\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
            \"withdrawalsRoot\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"
        },
        \"genesisRLP\" : \"0xf90218f90212a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa09f91e48451b763f8f7a3388d1748f55e3251e31fcb3f06af8969c125432e93aba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008080830f4240808000a000000000000000000000000000000000000000000000000000000000000200008800000000000000000ba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421c0c0c0\",
        \"lastblockhash\" : \"0xea6ffca9824f1c6d6d388cd891c9431c98c0884ba4c1568eb878824d285cd925\",
        \"network\" : \"Shanghai\",
        \"postState\" : {
            \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\" : {
                \"balance\" : \"0x01\",
                \"code\" : \"0x73095e7baea6a6c7c4c2dfeb977efac326af552d873173095e7baea6a6c7c4c2dfeb977efac326af552d873173095e7baea6a6c7c4c2dfeb977efac326af552d87310860005500\",
                \"nonce\" : \"0x00\",
                \"storage\" : {
                }
            },
            \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\" : {
                \"balance\" : \"0x0de0b6b3a760693f\",
                \"code\" : \"0x\",
                \"nonce\" : \"0x01\",
                \"storage\" : {
                }
            }
        },
        \"pre\" : {
            \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\" : {
                \"balance\" : \"0x00\",
                \"code\" : \"0x73095e7baea6a6c7c4c2dfeb977efac326af552d873173095e7baea6a6c7c4c2dfeb977efac326af552d873173095e7baea6a6c7c4c2dfeb977efac326af552d87310860005500\",
                \"nonce\" : \"0x00\",
                \"storage\" : {
                }
            },
            \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\" : {
                \"balance\" : \"0x0de0b6b3a7640000\",
                \"code\" : \"0x\",
                \"nonce\" : \"0x00\",
                \"storage\" : {
                }
            }
        },
        \"sealEngine\" : \"NoProof\"
    }}
    ";
    const BLOCK_JSON: &str = "
    [{
        \"blockHeader\" : {
            \"bloom\" : \"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",
            \"coinbase\" : \"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba\",
            \"difficulty\" : \"0x020000\",
            \"extraData\" : \"0x00\",
            \"gasLimit\" : \"0x0f4240\",
            \"gasUsed\" : \"0x5d70\",
            \"hash\" : \"0x668c5d6c12a905b58fc597b3146d29b9d12280c1891449b06e19f9edee0fe86f\",
            \"mixHash\" : \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"nonce\" : \"0x0000000000000000\",
            \"number\" : \"0x01\",
            \"parentHash\" : \"0xd86c2d4e6439870452a6c52b71fc6f06d9f98e53c5f9c47acd0ab3c04e73ef7b\",
            \"receiptTrie\" : \"0xb34b65874cf7cb8358930db57604b2f6610f98c25f2b5822cc25adee7f181ff5\",
            \"stateRoot\" : \"0xf17157ed407eb909de943044b712ab5db7f48c3557e3a3d8e17b1d8b426a1916\",
            \"timestamp\" : \"0x03e8\",
            \"transactionsTrie\" : \"0x174ccc4f3050aca8eb96ee492d7f77c48698de3988b3a422e2bc6974348182c0\",
            \"uncleHash\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"
        },
        \"rlp\" : \"0xf9025ff901f7a0d86c2d4e6439870452a6c52b71fc6f06d9f98e53c5f9c47acd0ab3c04e73ef7ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0f17157ed407eb909de943044b712ab5db7f48c3557e3a3d8e17b1d8b426a1916a0174ccc4f3050aca8eb96ee492d7f77c48698de3988b3a422e2bc6974348182c0a0b34b65874cf7cb8358930db57604b2f6610f98c25f2b5822cc25adee7f181ff5b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008302000001830f4240825d708203e800a00000000000000000000000000000000000000000000000000000000000000000880000000000000000f862f860800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d8701801ca09d46b87169053cc40670aef750b032c895cde3e35c2c7f5a37c059272e0914c7a04d4a94b67b2776cc3e0fca2ed9503c10fd92ec79f1b2dcbb85df9634c7de3119c0\",
        \"transactions\" : [
            {
                \"data\" : \"0x\",
                \"gasLimit\" : \"0x061a80\",
                \"gasPrice\" : \"0x0a\",
                \"nonce\" : \"0x00\",
                \"r\" : \"0x9d46b87169053cc40670aef750b032c895cde3e35c2c7f5a37c059272e0914c7\",
                \"s\" : \"0x4d4a94b67b2776cc3e0fca2ed9503c10fd92ec79f1b2dcbb85df9634c7de3119\",
                \"sender\" : \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\",
                \"to\" : \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\",
                \"v\" : \"0x1c\",
                \"value\" : \"0x01\"
            }
        ],
        \"uncleHeaders\" : [
        ]
    }]
    ";

    #[test]
    fn deserialize_hex_str_works() {
        let byte_str: ByteString = serde_json::from_str(TEST_HEX_STR).unwrap();

        assert_eq!(byte_str.0[0], 0xf8);
        assert_eq!(byte_str.0[1], 0x63);

        assert_eq!(byte_str.0[byte_str.0.len() - 1], 0x16);
        assert_eq!(byte_str.0[byte_str.0.len() - 2], 0x6e);
    }

    #[test]
    fn deserialize_blockchain_test() {
        let _block: Vec<Block> = serde_json::from_str(BLOCK_JSON).unwrap();
        if let TestBody::BlockchainTestBody(body) = serde_json::from_str(BLOCKCHAIN_TEST_JSON).unwrap() {
            assert_eq!(body.blocks[0].block_header.gas_limit, U256::from(0x0f4240));
            assert_eq!(body.genesis_block_header.gas_limit, U256::from(0x0f4240));
            return
        }
        panic!()        
    }

    #[test]
    fn deserialize_general_state_test() {
        let body: TestBody = serde_json::from_str(GENERALSTATE_TEST_JSON).unwrap();
        if let TestBody::GeneralStateTestBody(body) = body {
            assert_eq!(body.post.shanghai[0].hash, H256::from(hex!("82839135ead533b540a4894ed296a14f5ff764e53a10d6ab15e12941d8adeb91")));
        }
        else {
            panic!()
        }
    }
}
