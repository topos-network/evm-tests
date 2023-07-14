//! Filesystem helpers. A set of convenience functions for interacting with test
//! input and output directories.
use std::{
    collections::HashMap,
    fs::{self, DirEntry, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Result};
use common::config::GENERATION_INPUTS_DEFAULT_OUTPUT_DIR;
use plonky2_evm::proof::BlockMetadataTarget;

use crate::deserialize::TestBody;
use crate::{
    config::{BLOCKCHAIN_TEST_DIR, ETH_TESTS_REPO_LOCAL_PATH, GENERAL_TEST_GROUPS},
    deserialize::{BlockchainTestBody, GeneralStateTestBody},
};

/// Get the default parsed test output directory.
/// We first check if the flat file, `ETH_TEST_PARSER_DEV`, exists
/// in the current working directory. If so, we assume we're in a development
/// context, and default to the project root. Otherwise, we cannot make any
/// assumptions, fall back to the `GENERATION_INPUTS_DEFAULT_OUTPUT_DIR` value.
pub(crate) fn get_default_out_dir() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    let mut dev_check_path = cwd.clone();
    dev_check_path.push("ETH_TEST_PARSER_DEV");
    if dev_check_path.exists() {
        let mut out_dir = cwd
            .parent()
            .ok_or_else(|| {
                anyhow!(
                    "Unable to read cwd path parent. {:?} has no parent.",
                    cwd.as_os_str()
                )
            })?
            .to_path_buf();
        out_dir.push(GENERATION_INPUTS_DEFAULT_OUTPUT_DIR);
        Ok(out_dir)
    } else {
        Ok(GENERATION_INPUTS_DEFAULT_OUTPUT_DIR.into())
    }
}

/// Generate an iterator over the outer test group folders.
///
/// Expected directory structure
/// ```ignore
/// // {TestGroupN} <--- HERE
/// // ├── {TestNameN}
/// // │   ├── {test_case_1}.json
/// // │   └── {test_case_n}.json
/// ```
pub(crate) fn get_test_group_dirs<const N: usize>(
    sub_dir: &str,
    test_groups: &'static [&str; N],
) -> Result<impl Iterator<Item = DirEntry>> {
    let dirs = fs::read_dir(ETH_TESTS_REPO_LOCAL_PATH.to_owned() + "/" + sub_dir)?
        .flatten()
        .filter(|entry| match entry.file_name().to_str() {
            Some(file_name) => test_groups.contains(&file_name),
            None => false,
        });
    Ok(dirs)
}

/// Generate an iterator over the inner test group folders.
///
/// Expected directory structure
/// ```ignore
/// // {TestGroupN}
/// // ├── {TestNameN} <--- HERE
/// // │   ├── {test_case_1}.json
/// // │   └── {test_case_n}.json
/// ```
pub(crate) fn get_test_group_sub_dirs<const N: usize>(
    sub_dir: &str,
    test_group: &'static [&str; N],
) -> Result<impl Iterator<Item = DirEntry>> {
    let dirs = get_test_group_dirs(sub_dir, test_group)?
        .flat_map(|entry| fs::read_dir(entry.path()))
        .flatten()
        .flatten();
    Ok(dirs)
}

/// Generate an iterator over the entire set of inner test case files.
///
/// Expected directory structure
/// ```ignore
/// // {TestGroupN}
/// // ├── {TestNameN}
/// // │   ├── {test_case_1}.json  <--- HERE
/// // │   └── {test_case_n}.json
/// ```
pub(crate) fn get_test_files() -> Result<impl Iterator<Item = (DirEntry, DirEntry)>> {
    let dirs_general_state_tests = get_test_group_sub_dirs(&"", &GENERAL_TEST_GROUPS)?
        .flat_map(|entry| fs::read_dir(entry.path()))
        .flatten()
        .flatten()
        .filter(|entry| match entry.path().extension() {
            None => false,
            Some(ext) => ext == "json",
        });

    // Alonso del futuro: Este zip debe ser mejor hacerlo cuando se llama a
    // get_test_files agregando el argumento path a get_test_files
    let dirs_blockchain_tests: Vec<DirEntry> =
        get_test_group_sub_dirs(&BLOCKCHAIN_TEST_DIR, &GENERAL_TEST_GROUPS)?
            .flat_map(|entry| fs::read_dir(entry.path()))
            .flatten()
            .flatten()
            .filter(|entry| match entry.path().extension() {
                None => false,
                Some(ext) => ext == "json",
            })
            .collect();
    Ok(dirs_general_state_tests.zip(dirs_blockchain_tests))
}

/// Create output directories mirroring the structure of source test
/// directories.
pub(crate) fn prepare_output_dir(out_path: &Path) -> Result<()> {
    for dir in get_test_group_sub_dirs("", &GENERAL_TEST_GROUPS)? {
        fs::create_dir_all(out_path.join(dir.path().strip_prefix(ETH_TESTS_REPO_LOCAL_PATH)?))?
    }
    // Do the same for blockchain tests?
    // for dir in get_test_group_sub_dirs(&BLOCKCHAIN_TEST_DIR)? {
    //     fs::create_dir_all(out_path.join(dir.path().
    // strip_prefix(ETH_TESTS_REPO_LOCAL_PATH)?))? }

    Ok(())
}

/// Generate an iterator containing the deserialized test bodies (`TestBody`)
/// and their `DirEntry`s.
pub(crate) fn get_deserialized_test_bodies() -> Result<
    impl Iterator<
        Item = Result<
            (
                (DirEntry, GeneralStateTestBody),
                (DirEntry, BlockchainTestBody),
            ),
            (String, String),
        >,
    >,
> {
    Ok(
        get_test_files()?.map(|(general_state_test, blockchain_test)| {
            let general_state_test_body =
                get_deserialized_general_state_test_body(&general_state_test).map_err(|err| {
                    (
                        err.to_string(),
                        general_state_test.path().to_string_lossy().to_string(),
                    )
                })?;
            let blockchain_test_body = get_deserialized_blockchain_test_body(&blockchain_test)
                .map_err(|err| {
                    (
                        err.to_string(),
                        blockchain_test.path().to_string_lossy().to_string(),
                    )
                })?;
            Ok((
                (general_state_test, general_state_test_body),
                (blockchain_test, blockchain_test_body),
            ))
        }),
    )
}

fn get_deserialized_general_state_test_body(entry: &DirEntry) -> Result<GeneralStateTestBody> {
    let buf = BufReader::new(File::open(entry.path())?);
    let file_json: HashMap<String, GeneralStateTestBody> = serde_json::from_reader(buf)?;

    let mut test_body_values = file_json.into_values();
    let next = test_body_values.next();
    let test_body = next.ok_or_else(|| anyhow!("Empty test found: {:?}", entry))?;

    anyhow::Ok(test_body)
}

fn get_deserialized_blockchain_test_body(entry: &DirEntry) -> Result<BlockchainTestBody> {
    let buf = BufReader::new(File::open(entry.path())?);
    let file_json: HashMap<String, BlockchainTestBody> = serde_json::from_reader(buf)?;

    for (k, v) in file_json.into_iter() {
        if k.ends_with("_Shanghai") {
            return anyhow::Ok(v);
        }
    }
    bail!("Couldn't deserialize blochckain test")
}
