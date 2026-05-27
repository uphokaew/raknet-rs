//! Modern Rust implementation of modified RakNet 2.52 extensions used in SA-MP and open.mp.
//!
//! Provides protocol features:
//! - Customized RakNet packet encryption and decryption
//! - Anti-DOS verification cookies (IP-dependent u16 cookies)
//! - Challenge-response client authentication table (AuthTable)
//! - UDP Server Query Protocol codec
//! - Connection state validation manager (handshake checks and connection limits)

pub mod crypto;
pub mod auth;
pub mod cookie;
pub mod query;
pub mod conn;
pub mod bitstream;
pub mod datagram;
pub mod tis620;
pub mod rpc;

// Re-export common items for easier usage
pub use crypto::{decrypt, encrypt, decrypt_in_place, encrypt_into, DECRYPT_KEY_TABLE};
pub use auth::{generate_auth, check_auth, AUTH_TABLE, AuthEntry};
pub use cookie::CookieJar;
pub use query::{QueryPacket, QueryPayload, QueryHeader, QueryPlayer, QueryError, BASE_QUERY_SIZE};
pub use conn::{
    ConnectionManager, ConnectionLimits, HandshakeResult, RejectionReason,
    ID_OPEN_CONNECTION_COOKIE, ID_USER_PACKET_ENUM, MAGIC_OMP_IDENTIFICATION_NUMBER,
    OMP_PETARDED, SAMP_PETARDED,
};
pub use bitstream::{BitStream, SafeBufCast};
pub use datagram::{
    Datagram, InternalPacket, RangeList, RangeNode,
    UNRELIABLE, UNRELIABLE_SEQUENCED, RELIABLE, RELIABLE_ORDERED, RELIABLE_SEQUENCED,
};
pub use tis620::{encode_tis620, decode_tis620};
