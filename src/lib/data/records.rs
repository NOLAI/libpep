//! Record types for encrypting multiple pseudonyms and attributes together.
//!
//! A `Record` represents a collection of pseudonyms and attributes that belong to the same entity.
//! When encrypted, it becomes an `EncryptedRecord`.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The shape of a [`Record`]: how many pseudonyms and attributes it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStructure {
    /// The number of pseudonyms.
    pub num_pseudonyms: usize,
    /// The number of attributes.
    pub num_attributes: usize,
}

/// The shape of a [`LongRecord`]: the number of blocks of every pseudonym and attribute.
#[cfg(feature = "long")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongRecordStructure {
    /// Number of blocks in each long pseudonym
    pub pseudonym_blocks: Vec<usize>,
    /// Number of blocks in each long attribute
    pub attribute_blocks: Vec<usize>,
}

/// The [`Record`](generic::Record) over ristretto255.
pub type Record = generic::Record<Ristretto255>;
/// The [`EncryptedRecord`](generic::EncryptedRecord) over ristretto255.
pub type EncryptedRecord = generic::EncryptedRecord<Ristretto255>;
/// The [`LongRecord`](generic::LongRecord) over ristretto255.
#[cfg(feature = "long")]
pub type LongRecord = generic::LongRecord<Ristretto255>;
/// The [`LongEncryptedRecord`](generic::LongEncryptedRecord) over ristretto255.
#[cfg(feature = "long")]
pub type LongEncryptedRecord = generic::LongEncryptedRecord<Ristretto255>;

#[cfg(all(test, feature = "long"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
    use crate::data::simple::{ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym};
    use crate::elgamal::ElGamal;
    use crate::errors::ParseError;

    fn ciphertext() -> ElGamal {
        let rng = &mut rand::rng();
        let y = crate::elgamal::arithmetic::scalars::ScalarNonZero::random(rng);
        let m = crate::elgamal::arithmetic::group_elements::GroupElement::random(rng);
        crate::elgamal::encrypt(
            &m,
            &(y * crate::elgamal::arithmetic::group_elements::G),
            rng,
        )
    }

    /// A record of one long value without blocks is distinct from a record without values.
    #[test]
    fn long_record_string_round_trips_empty_values() {
        let records = [
            LongEncryptedRecord::new(vec![], vec![]),
            LongEncryptedRecord::new(vec![LongEncryptedPseudonym(vec![])], vec![]),
            LongEncryptedRecord::new(
                vec![LongEncryptedPseudonym(vec![
                    EncryptedPseudonym::from_value(ciphertext()),
                ])],
                vec![
                    LongEncryptedAttribute(vec![]),
                    LongEncryptedAttribute(vec![EncryptedAttribute::from_value(ciphertext())]),
                ],
            ),
        ];
        for record in records {
            let encoded = record.serialize();
            assert_eq!(LongEncryptedRecord::deserialize(&encoded).unwrap(), record);
        }
        assert_eq!(
            LongEncryptedRecord::deserialize("2:;0:"),
            Err(ParseError::InvalidCount("2:".to_string()))
        );
        assert!(LongEncryptedRecord::deserialize(";").is_err());
    }
}
