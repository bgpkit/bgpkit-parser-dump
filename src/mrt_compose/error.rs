use thiserror::Error;
use crate::DumpError;

#[derive(Error, Debug)]
pub enum ComposeError {
    #[error(transparent)]
    DumpError(#[from] DumpError),

    #[error("{0}")]
    ComposeError(String),
}
