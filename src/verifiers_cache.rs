use crate::distributed::PEPSystemID;
use std::collections::HashMap;
use std::hash::Hash;

pub trait VerifiersCache {
    type Key;
    type Verifiers;

    fn new() -> Self
    where
        Self: Sized;
    fn store(&mut self, system_id: PEPSystemID, context: Self::Key, verifiers: Self::Verifiers);
    fn retrieve(&self, system_id: &PEPSystemID, context: &Self::Key) -> Option<&Self::Verifiers>;
    fn has(&self, system_id: &PEPSystemID, context: &Self::Key) -> bool;
    fn contains(&self, verifiers: &Self::Verifiers) -> bool;
    fn dump(&self) -> Vec<(PEPSystemID, Self::Key, Self::Verifiers)>;

    #[must_use]
    fn is_valid(&self, system_id: &PEPSystemID, context: &Self::Key, verifiers: &Self::Verifiers) -> bool {
        // TODO check for weak edge cases
        true
    }
}

pub struct InMemoryVerifiersCache<Context, FactorVerifiers>
where
    Context: Eq + Hash,
{
    pub cache: HashMap<(PEPSystemID, Context), FactorVerifiers>,
}

impl<Context, FactorVerifiers> InMemoryVerifiersCache<Context, FactorVerifiers>
where
    Context: Eq + Hash,
{
    pub fn new() -> Self {
        InMemoryVerifiersCache {
            cache: HashMap::new(),
        }
    }
}

impl<Context, FactorVerifiers> VerifiersCache for InMemoryVerifiersCache<Context, FactorVerifiers>
where
    Context: Eq + Hash + Clone,
    FactorVerifiers: PartialEq + Clone,
{
    type Key = Context;
    type Verifiers = FactorVerifiers;

    fn new() -> Self {
        InMemoryVerifiersCache {
            cache: HashMap::new(),
        }
    }

    fn store(&mut self, system_id: PEPSystemID, context: Self::Key, verifiers: Self::Verifiers) {
        self.cache.insert((system_id.clone(), context.clone()), verifiers.clone());
    }

    fn retrieve(&self, system_id: &PEPSystemID, context: &Self::Key) -> Option<&Self::Verifiers> {
        self.cache.get(&(system_id.clone(), context.clone()))
    }

    fn has(&self, system_id: &PEPSystemID, context: &Self::Key) -> bool {
        self.cache.contains_key(&(system_id.clone(), context.clone()))
    }

    fn contains(&self, verifiers: &Self::Verifiers) -> bool {
        self.cache.values().any(|x| *x == *verifiers)
    }

    fn dump(&self) -> Vec<(PEPSystemID, Self::Key, Self::Verifiers)> {
        self.cache.iter().map(|((system_id, context), verifiers)| (system_id.clone(), context.clone(), verifiers.clone())).collect()
    }
}