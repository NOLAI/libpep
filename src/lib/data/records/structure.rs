//! The shapes of records.

/// The shape of a [`Record`](super::Record): how many pseudonyms and attributes it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStructure {
    /// The number of pseudonyms.
    pub num_pseudonyms: usize,
    /// The number of attributes.
    pub num_attributes: usize,
}

/// The shape of a [`LongRecord`](super::LongRecord): the number of blocks of every pseudonym and attribute.
#[cfg(feature = "long")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongRecordStructure {
    /// Number of blocks in each long pseudonym
    pub pseudonym_blocks: Vec<usize>,
    /// Number of blocks in each long attribute
    pub attribute_blocks: Vec<usize>,
}
