//! Distributed n-PEP with wrappers for high-level [`PEPSystems`](systems::PEPSystem) (*transcryptors*) and [`PEPClients`](systems::PEPClient).
//! This module is intended for use cases where transcryption is performed by *n* parties and
//! trust is distributed among them (i.e. no single party is trusted but the system remains secure
//! as long as at least 1 party remains honest).

pub mod key_blinding;
pub mod systems;
