use thiserror::Error;

#[derive(Error, Debug)]
pub enum DumpError {

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}