#![allow(dead_code)]
use std::{marker::PhantomData, fmt, str};
use std::collections::HashMap;
use std::str::FromStr;
use anyhow::{Result};
use ethereum_types::{Address, H160, H256, U256, U512};
use hex::FromHex;
use serde::de::MapAccess;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};
use serde_with::{serde_as, DefaultOnNull, NoneAsEmptyString};

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
#[derive(Clone, Deserialize, Debug, Default)]
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

// For deserializing bloom filters
fn vec_u256_from_hex<'de, D>(deserializer: D) -> Result<[U256; 8], D::Error>
where
    D: Deserializer<'de>
{
    let str: String = Deserialize::deserialize(deserializer)?;
    let el_valor: Result<Vec<_>, _> = str[2..].chars().collect::<Vec<char>>()
        .chunks(64)
        .map(|str|
            U256::from_str_radix(&str.iter().collect::<String>()[..], 16).map_err(D::Error::custom)
        )
        .collect();
    if let Ok(el_valor) = el_valor {
        if el_valor.len() < 8 {
            return Err(D::Error::custom("Field bloom too short"))
        }
        else{
            return Ok([el_valor[0], el_valor[1], el_valor[2], el_valor[3], el_valor[4], el_valor[5], el_valor[6], el_valor[7]])
        }
    }
    Err(D::Error::custom("Invalid bloom field"))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Env {
    pub(crate) current_base_fee: U256,
    pub(crate) current_coinbase: H160,
    pub(crate) current_difficulty: U256,
    pub(crate) current_gas_limiting: U256,
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
    #[serde(deserialize_with = "check_if_decodes")]
    pub(crate) txbytes: ByteString,
}

fn check_if_decodes<'de, D>(deserializer: D) -> Result<ByteString, D::Error>
where
    D: Deserializer<'de>,
{
    let txbytes: ByteString = Deserialize::deserialize(deserializer)?;
    //let _decoded_txn = rlp::decode::<LegacyTransactionRlp>(&txbytes.0).map_err(D::Error::custom)?;
    Ok(txbytes)
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
    // pub(crate) data:ByteString,
    // pub(crate) gas_limit: U256,
    // #[serde(default)] // Non legacy txns don't have this field
    // pub(crate) gas_price: U256,
    // pub(crate) nonce: U256,
    // #[serde(default)]
    // pub(crate) secret_key: H256,
    // pub(crate) sender: H160,
    // #[serde_as(as = "NoneAsEmptyString")]
    // pub(crate) to: Option<H160>,
    // // Protect against overflow.
    // pub(crate) value: U512,
    pub(crate) v: U256,
    pub(crate) r: U256,
    pub(crate) s: U256,
}

impl TransactionBlockchainTest {
    // pub fn as_legacy_transaction(&self) -> LegacyTransactionRlp {
    //     LegacyTransactionRlp {
    //         nonce: self.nonce,
    //         gas_price: self.gas_price,
    //         gas: self.gas_limit,
    //         to: self.to,
    //         value: U256::try_from(self.value).expect("Transaction value too large"),
    //         data: self.data.clone(),
    //         v: self.v,
    //         r: self.r,
    //         s: self.s,
    //     }
    // }
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

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BlockHeader {
    // #[serde(default)]
    // pub(crate) base_fee_per_gas: U256,
    #[serde(deserialize_with = "vec_u256_from_hex")]
    pub(crate) bloom: [U256; 8],
    // pub(crate) coinbase: H160,
    // pub(crate) difficulty: U256,
    // pub(crate) extra_data: ByteString,
    pub(crate) gas_limit: U256,
    pub(crate) gas_used: U256,
    // pub(crate) hash: H256,
    // pub(crate) mix_hash: H256,
    // pub(crate) nonce: U256,
    // pub(crate) number: U256,
    // pub(crate) parent_hash: H256,
    pub(crate) receipt_trie: H256,
    pub(crate) state_root: H256,
    // pub(crate) timestamp: U256,
    pub(crate) transactions_trie: H256,
    // pub(crate) uncle_hash: H256
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Block {
    #[serde(default, rename = "blockHeader")]
    pub(crate) block_header_original: BlockHeader,
    #[serde(rename = "rlp", deserialize_with = "block_header_from_rlp")]
    pub(crate) block_header: BlockHeader,
    #[serde(default)]
    pub(crate) transactions: Vec<TransactionBlockchainTest>,
    #[serde(default)]
    pub(crate) transaction_sequence: Vec<TransactionSequence>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransactionSequence {
    pub(crate) raw_bytes: ByteString
}

fn block_header_from_rlp<'de, D>(deserializer: D) -> Result<BlockHeader, D::Error>
where
    D: Deserializer<'de>
{
    let bytes: ByteString = Deserialize::deserialize(deserializer)?;
    let rlp = rlp::Rlp::new(&bytes.0)
        .at(0)
        .map_err(D::Error::custom)?;

    let bloom: Vec<u8> = rlp.at(6)
        .map_err(D::Error::custom)?
        .as_val()
        .map_err(D::Error::custom)?;
    if bloom.len() != 256 {
        return Err(D::Error::custom("Wrong bloom field"));
    }
    let bloom = [
        U256::from(&bloom[0..32]), 
        U256::from(&bloom[32..64]),
        U256::from(&bloom[64..96]),
        U256::from(&bloom[96..123]),
        U256::from(&bloom[128..160]),
        U256::from(&bloom[160..192]),
        U256::from(&bloom[192..224]),
        U256::from(&bloom[224..256])
    ];

    let gas_limit = rlp
        .at(9)
        .map_err(D::Error::custom)?
        .as_val()
        .map_err(D::Error::custom)?;
    let gas_used = rlp
        .at(9)
        .map_err(D::Error::custom)?
        .as_val()
        .map_err(D::Error::custom)?;

    let receipt_trie = rlp
        .at(5)
        .map_err(D::Error::custom)?
        .as_val()
        .map_err(D::Error::custom)?;
    let state_root = rlp
        .at(3)
        .map_err(D::Error::custom)?
        .as_val()
        .map_err(D::Error::custom)?;
    let transactions_trie = rlp
        .at(4)
        .map_err(D::Error::custom)?
        .as_val()
        .map_err(D::Error::custom)?;
    
    Ok(BlockHeader { 
        bloom, 
        gas_limit, 
        gas_used, 
        receipt_trie, 
        state_root, 
        transactions_trie,
    })
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BlockchainTestBody {
    #[serde(deserialize_with = "one_element")]
    pub(crate) blocks: Vec<Block>,
    pub(crate) genesis_block_header: BlockHeader,
    // pub(crate) genesis_r_l_p: ByteString, // How to make it genesis_rlp?,
    // pub(crate) lastblockhash: H256,
    // #[serde(default)]
    // pub(crate) post_state: HashMap<H160, PreAccount>, // TODO: Doesn't seem correct
    // pub(crate) pre: HashMap<H160, PreAccount>,
}

fn one_element<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let vec = <Vec<T>>::deserialize(d)?;
    if vec.len() != 1 {
        Err(D::Error::custom("need array of size 1"))
    } else {
        Ok(vec)
    }
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
    {\"log3_PC_d0g0v0_Shanghai\" : {
        \"_info\" : {
            \"comment\" : \"\",
            \"filling-rpc-server\" : \"evm version 1.11.4-unstable-e14043db-20230308\",
            \"filling-tool-version\" : \"retesteth-0.3.0-shanghai+commit.fd2c0a83.Linux.g++\",
            \"generatedTestHash\" : \"01b293987031bc3552d7af9918f7ef9734dae3f4d155da9e6525045f45f5dd53\",
            \"lllcversion\" : \"Version: 0.5.14-develop.2022.7.30+commit.a096d7a9.Linux.g++\",
            \"solidity\" : \"Version: 0.8.17+commit.8df45f5f.Linux.g++\",
            \"source\" : \"src/GeneralStateTestsFiller/stLogTests/log3_PCFiller.json\",
            \"sourceHash\" : \"2f8d587199dfb91ea2fc04d813106e6c3ceace220a37160a01c6c0dc9b6864a6\"
        },
        \"blocks\" : [
            {
                \"blockHeader\" : {
                    \"baseFeePerGas\" : \"0x0a\",
                    \"bloom\" : \"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000400000000000000000000000030000000000000000000000000000000000000000000000008800000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000001000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000800000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000\",
                    \"coinbase\" : \"0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba\",
                    \"difficulty\" : \"0x00\",
                    \"extraData\" : \"0x00\",
                    \"gasLimit\" : \"0x0f4240\",
                    \"gasUsed\" : \"0xd3bc\",
                    \"hash\" : \"0x00bccb0f353b26f76ce28883294863638c940cbe5e9f1fb3965957aba3901549\",
                    \"mixHash\" : \"0x0000000000000000000000000000000000000000000000000000000000020000\",
                    \"nonce\" : \"0x0000000000000000\",
                    \"number\" : \"0x01\",
                    \"parentHash\" : \"0xe03fd0bb095359251d6b3bea3251cf4287fdf054bc73f47f96a75bcc10d14611\",
                    \"receiptTrie\" : \"0xd009c250cc6afeb6d89fbc5a5838fb60709345da76518ea9f5ec2a5a2e2b4d3c\",
                    \"stateRoot\" : \"0x6477162eaa7bd8b63f17d1efc7e481129feed01e6eba2c7766f3a73e1ac5f28f\",
                    \"timestamp\" : \"0x03e8\",
                    \"transactionsTrie\" : \"0x9b55322a19d9b3b71be0f5c6f5dbf194748d3290bcfa35d1706c1a24ff105a5f\",
                    \"uncleHash\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
                    \"withdrawalsRoot\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"
                },
                \"rlp\" : \"0xf90282f90216a0e03fd0bb095359251d6b3bea3251cf4287fdf054bc73f47f96a75bcc10d14611a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa06477162eaa7bd8b63f17d1efc7e481129feed01e6eba2c7766f3a73e1ac5f28fa09b55322a19d9b3b71be0f5c6f5dbf194748d3290bcfa35d1706c1a24ff105a5fa0d009c250cc6afeb6d89fbc5a5838fb60709345da76518ea9f5ec2a5a2e2b4d3cb90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000004000000000000000000000000300000000000000000000000000000000000000000000000088000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000010000008000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000008000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000008001830f424082d3bc8203e800a000000000000000000000000000000000000000000000000000000000000200008800000000000000000aa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421f865f863800a8303345094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0d7f12f33fd6ed868181c442fa795b825833472c08304ba8076c99e361277a1cea00754e3b3f79c4ac1554e25989ea8422b5dde0a09c4ff362ad4086d3f3a7d63cfc0c0\",
                \"transactions\" : [
                    {
                        \"data\" : \"0x\",
                        \"gasLimit\" : \"0x033450\",
                        \"gasPrice\" : \"0x0a\",
                        \"nonce\" : \"0x00\",
                        \"r\" : \"0xd7f12f33fd6ed868181c442fa795b825833472c08304ba8076c99e361277a1ce\",
                        \"s\" : \"0x0754e3b3f79c4ac1554e25989ea8422b5dde0a09c4ff362ad4086d3f3a7d63cf\",
                        \"sender\" : \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\",
                        \"to\" : \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\",
                        \"v\" : \"0x1b\",
                        \"value\" : \"0x0186a0\"
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
            \"hash\" : \"0xe03fd0bb095359251d6b3bea3251cf4287fdf054bc73f47f96a75bcc10d14611\",
            \"mixHash\" : \"0x0000000000000000000000000000000000000000000000000000000000020000\",
            \"nonce\" : \"0x0000000000000000\",
            \"number\" : \"0x00\",
            \"parentHash\" : \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"receiptTrie\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",
            \"stateRoot\" : \"0xf412ce643d392f2ddd4d212ef4159df06eb41c163162e8e42289ee61d437f525\",
            \"timestamp\" : \"0x00\",
            \"transactionsTrie\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",
            \"uncleHash\" : \"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",
            \"withdrawalsRoot\" : \"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"
        },
        \"genesisRLP\" : \"0xf90218f90212a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0f412ce643d392f2ddd4d212ef4159df06eb41c163162e8e42289ee61d437f525a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008080830f4240808000a000000000000000000000000000000000000000000000000000000000000200008800000000000000000ba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421c0c0c0\",
        \"lastblockhash\" : \"0x00bccb0f353b26f76ce28883294863638c940cbe5e9f1fb3965957aba3901549\",
        \"network\" : \"Shanghai\",
        \"postState\" : {
            \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\" : {
                \"balance\" : \"0x0de0b6b3a7658689\",
                \"code\" : \"0x60006000600060006017730f572e5295c57f15886f9b263e2f6d2d6c7b5ec66103e8f160005500\",
                \"nonce\" : \"0x00\",
                \"storage\" : {
                    \"0x00\" : \"0x01\"
                }
            },
            \"0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6\" : {
                \"balance\" : \"0x0de0b6b3a7640017\",
                \"code\" : \"0x60ff60005358585860206000a300\",
                \"nonce\" : \"0x00\",
                \"storage\" : {
                }
            },
            \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\" : {
                \"balance\" : \"0x0de0b6b3a75a3408\",
                \"code\" : \"0x\",
                \"nonce\" : \"0x01\",
                \"storage\" : {
                }
            }
        },
        \"pre\" : {
            \"0x095e7baea6a6c7c4c2dfeb977efac326af552d87\" : {
                \"balance\" : \"0x0de0b6b3a7640000\",
                \"code\" : \"0x60006000600060006017730f572e5295c57f15886f9b263e2f6d2d6c7b5ec66103e8f160005500\",
                \"nonce\" : \"0x00\",
                \"storage\" : {
                }
            },
            \"0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6\" : {
                \"balance\" : \"0x0de0b6b3a7640000\",
                \"code\" : \"0x60ff60005358585860206000a300\",
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

    const FILE_PATH: &str = "../eth_tests/BlockchainTests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json";

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
            assert_eq!(body.blocks[0].block_header.bloom, body.blocks[0].block_header_original.bloom);
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

    // #[test]
    // fn deserialize_blockchain_test_from_file() {
    //     let buf = BufReader::new(File::open(FILE_PATH));
    //     if let TestBody::BlockchainTestBody(body) = serde_json::from_reader(buf)? {
    //         assert_eq!(body.blocks[0].block_header.gas_limit, U256::from(0x0f4240));
    //         assert_eq!(body.genesis_block_header.gas_limit, U256::from(0x0f4240));
    //         return
    //     }
    //     panic!()  
    // }
}
