//! Utilities constructing an in-memory [`revm`](revm) environment from a
//! [`TestBody`](crate::deserialize::TestBody).
//!
//! Getting a fully constructed [`revm`](revm) environment requires the
//! following steps:
//!
//! 1. Construct an [`EVM`](revm::EVM) instance.
//! 2. Configure the instance's [`Env`](revm::primitives::Env). Note this
//!    includes setting up the transaction we're testing at this step.
//! 3. Construct a [`Db`](revm::db::Database). In our case, an
//!    [`InMemoryDB`](revm::InMemoryDB).
//! 4. Load the database with the accounts and their storage.

use anyhow::Result;
use common::revm::SerializableEVMInstance;

use crate::deserialize::GeneralStateTestBody;

mod cache_db;
mod env;

impl GeneralStateTestBody {
    pub(crate) fn as_serializable_evm_instances(&self) -> Result<Vec<SerializableEVMInstance>> {
        let envs = self.as_revm_env()?;
        let db = self.as_revm_cache_db()?;

        Ok(envs
            .into_iter()
            .map(|env| SerializableEVMInstance {
                env,
                db: db.clone(),
            })
            .collect())
    }
}

impl TryFrom<GeneralStateTestBody> for Vec<SerializableEVMInstance> {
    type Error = anyhow::Error;

    fn try_from(body: GeneralStateTestBody) -> Result<Self> {
        body.as_serializable_evm_instances()
    }
}
