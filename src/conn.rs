//! High-level SA-MP and open.mp connection handshake and limits management.
//!
//! Provides connection handshake state tracking, cookie exchange logic,
//! and validation of connection requests matching the C++ behavior.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use crate::cookie::CookieJar;

/// Custom packet markers representing connection states.
pub const ID_OPEN_CONNECTION_COOKIE: u8 = 26; // 0x1A
pub const ID_USER_PACKET_ENUM: u8 = 134;       // 0x86

/// Magic constants used in the SA-MP/open.mp handshake.
pub const MAGIC_OMP_IDENTIFICATION_NUMBER: u32 = 0x006F6D70; // 'omp'
pub const OMP_PETARDED: u16 = 0x6D70;                        // 'mp'
pub const SAMP_PETARDED: u16 = 0x6969;                       // SA-MP custom magic

/// Handshake result indicating how the server should respond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeResult {
    /// Send a cookie request back to the client.
    ///
    /// The payload of this response packet should start with `ID_OPEN_CONNECTION_COOKIE` (1 byte)
    /// followed by the cookie value (2 bytes, little-endian).
    SendCookie(u16),

    /// Accept standard SA-MP connection.
    AcceptSAMP,

    /// Accept open.mp connection.
    ///
    /// Response should start with `ID_USER_PACKET_ENUM`, followed by
    /// `MAGIC_OMP_IDENTIFICATION_NUMBER` (4 bytes), encryption key (4 bytes), and client version (4 bytes).
    AcceptOMP {
        /// Generated player encryption key.
        encryption_key: u32,
        /// Current server OMP version.
        version: u32,
    },

    /// Connection request was ignored or rejected due to rate limits or duplicate requests.
    Rejected(RejectionReason),
}

/// Reasons why a connection request might be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// Request came in too fast (violates minimum connection time).
    RateLimited,
    /// Connection request is already in progress.
    AlreadyRequesting,
}

/// Server configuration for connection limits.
#[derive(Debug, Clone)]
pub struct ConnectionLimits {
    /// Minimum duration between connection attempts from the same IP.
    pub min_connection_time: Duration,
    /// Time when the server is in "grace period" (unlimited connections allowed).
    pub grace_period_until: Option<Instant>,
    /// Set to true to bypass checks for localhost connections.
    pub bypass_localhost: bool,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            min_connection_time: Duration::from_millis(0),
            grace_period_until: None,
            bypass_localhost: true,
        }
    }
}

/// Manages incoming connection handshakes, limits, and anti-DOS cookies.
#[derive(Debug, Clone)]
pub struct ConnectionManager {
    /// Jar containing anti-DOS cookies.
    cookie_jar: CookieJar,
    /// Tracks active connection request IPs.
    incoming_connections: HashSet<Ipv4Addr>,
    /// Tracks the last connection request timestamp per IP.
    last_connection_ticks: HashMap<Ipv4Addr, Instant>,
    /// Configuration limits.
    limits: ConnectionLimits,
    /// Current OMP client mod version supported.
    omp_version: u32,
}

impl ConnectionManager {
    /// Creates a new `ConnectionManager` with the specified cookie jar and defaults.
    pub fn new(cookie_jar: CookieJar, omp_version: u32) -> Self {
        Self {
            cookie_jar,
            incoming_connections: HashSet::new(),
            last_connection_ticks: HashMap::new(),
            limits: ConnectionLimits::default(),
            omp_version,
        }
    }

    /// Sets connection limits.
    pub fn set_limits(&mut self, limits: ConnectionLimits) {
        self.limits = limits;
    }

    /// Checks if an IP is currently requesting a connection.
    pub fn is_requesting(&self, ip: Ipv4Addr) -> bool {
        self.incoming_connections.contains(&ip)
    }

    /// Sets the connection request status for an IP.
    pub fn set_requesting(&mut self, ip: Ipv4Addr, status: bool) {
        if status {
            self.incoming_connections.insert(ip);
        } else {
            self.incoming_connections.remove(&ip);
        }
    }

    /// Processes an incoming connection request packet.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use raknet_rs::{ConnectionManager, CookieJar, HandshakeResult};
    ///
    /// let jar = CookieJar::new_seeded();
    /// let mut manager = ConnectionManager::new(jar, 0x000104);
    /// let ip = Ipv4Addr::new(127, 0, 0, 1);
    ///
    /// // Handle packet request ID 11
    /// let result = manager.handle_connection_request(ip, &[11], || 0x12345678);
    /// assert!(matches!(result, HandshakeResult::SendCookie(_)));
    /// ```
    ///
    /// # Arguments
    /// * `ip` - The IPv4 address of the sender.
    /// * `payload` - The raw packet payload (minimum 3 bytes for cookie parsing).
    /// * `rng_key` - A function or value providing a new random 32-bit key if OMP is accepted.
    pub fn handle_connection_request<F>(&mut self, ip: Ipv4Addr, payload: &[u8], rng_key: F) -> HandshakeResult
    where
        F: FnOnce() -> u32,
    {
        // 1. Reset OMP player configuration for this address implicitly by starting checks.

        // 2. Perform connection rate limit checks
        let now = Instant::now();
        let is_localhost = ip.is_loopback() || ip == Ipv4Addr::new(127, 0, 0, 1);
        let in_grace_period = self
            .limits
            .grace_period_until
            .map(|until| now < until)
            .unwrap_or(false);

        if !(in_grace_period || (is_localhost && self.limits.bypass_localhost)) {
            if self.incoming_connections.contains(&ip) {
                return HandshakeResult::Rejected(RejectionReason::AlreadyRequesting);
            }

            if self.limits.min_connection_time > Duration::from_millis(0)
                && self.last_connection_ticks.get(&ip).is_some_and(|&last_tick| {
                    now.duration_since(last_tick) < self.limits.min_connection_time
                })
            {
                return HandshakeResult::Rejected(RejectionReason::RateLimited);
            }
        }

        if self.limits.min_connection_time > Duration::from_millis(0) {
            // Update the last connection request tick
            self.last_connection_ticks.insert(ip, now);

            // Clean up obsolete entries if the map gets too large
            if self.last_connection_ticks.len() > 1000 {
                let min_time = self.limits.min_connection_time;
                self.last_connection_ticks.retain(|_, &mut last_tick| {
                    now.duration_since(last_tick) < min_time
                });
            }
        }

        // 3. Verify connection cookie.
        // The packet payload from client: Byte 0 (Packet ID), Bytes 1-2 (XORed cookie value).
        if payload.len() < 3 {
            // If the request doesn't even contain the cookie field, request a new cookie.
            let cookie = self.cookie_jar.get_cookie(ip);
            return HandshakeResult::SendCookie(cookie);
        }

        let client_xord_cookie = u16::from_le_bytes([payload[1], payload[2]]);
        let server_cookie = self.cookie_jar.get_cookie(ip);

        if (client_xord_cookie ^ SAMP_PETARDED) != server_cookie {
            if (client_xord_cookie ^ OMP_PETARDED) != server_cookie {
                // Cookie mismatch: Send client the server cookie
                HandshakeResult::SendCookie(server_cookie)
            } else {
                // open.mp client match: Accept with OMP details
                let key = rng_key();
                HandshakeResult::AcceptOMP {
                    encryption_key: key,
                    version: self.omp_version,
                }
            }
        } else {
            // SA-MP client match: Accept connection
            HandshakeResult::AcceptSAMP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flow() {
        let mut jar = CookieJar::new();
        // Set predictable cookies
        for i in 0..256 {
            jar.cookies[0][i] = i as u16;
            jar.cookies[1][i] = 0;
        }

        let omp_version = 0x000104; // v0.1.4
        let mut manager = ConnectionManager::new(jar.clone(), omp_version);

        let client_ip = Ipv4Addr::new(100, 0, 0, 1);
        let server_cookie = jar.get_cookie(client_ip);

        // 1. Initial request with no cookie payload
        let result1 = manager.handle_connection_request(client_ip, &[11], || 0x12345678);
        assert_eq!(result1, HandshakeResult::SendCookie(server_cookie));

        // 2. Client responds with incorrect cookie
        let result2 = manager.handle_connection_request(client_ip, &[11, 0xFF, 0xFF], || 0x12345678);
        assert_eq!(result2, HandshakeResult::SendCookie(server_cookie));

        // 3. Client responds with valid SAMP cookie: xordCookie = server_cookie ^ SAMP_PETARDED
        let samp_cookie_val = server_cookie ^ SAMP_PETARDED;
        let samp_cookie_bytes = samp_cookie_val.to_le_bytes();
        let result3 = manager.handle_connection_request(
            client_ip,
            &[11, samp_cookie_bytes[0], samp_cookie_bytes[1]],
            || 0x12345678,
        );
        assert_eq!(result3, HandshakeResult::AcceptSAMP);

        // 4. Client responds with valid OMP cookie: xordCookie = server_cookie ^ OMP_PETARDED
        let omp_cookie_val = server_cookie ^ OMP_PETARDED;
        let omp_cookie_bytes = omp_cookie_val.to_le_bytes();
        let result4 = manager.handle_connection_request(
            client_ip,
            &[11, omp_cookie_bytes[0], omp_cookie_bytes[1]],
            || 0x12345678,
        );
        assert_eq!(
            result4,
            HandshakeResult::AcceptOMP {
                encryption_key: 0x12345678,
                version: omp_version
            }
        );
    }

    #[test]
    fn test_rate_limits() {
        let jar = CookieJar::new_seeded();
        let mut manager = ConnectionManager::new(jar, 0x000104);
        manager.set_limits(ConnectionLimits {
            min_connection_time: Duration::from_millis(500),
            grace_period_until: None,
            bypass_localhost: false, // Turn off bypass to test limits
        });

        let client_ip = Ipv4Addr::new(10, 0, 0, 5);

        // First attempt - requests cookie
        let res1 = manager.handle_connection_request(client_ip, &[11], || 0);
        assert!(matches!(res1, HandshakeResult::SendCookie(_)));

        // Second attempt immediately after - rate limited!
        let res2 = manager.handle_connection_request(client_ip, &[11], || 0);
        assert_eq!(res2, HandshakeResult::Rejected(RejectionReason::RateLimited));

        // Wait for limits to expire
        std::thread::sleep(Duration::from_millis(550));

        // Third attempt - allowed again
        let res3 = manager.handle_connection_request(client_ip, &[11], || 0);
        assert!(matches!(res3, HandshakeResult::SendCookie(_)));
    }

    #[test]
    fn test_rate_limits_eviction() {
        let jar = CookieJar::new_seeded();
        let mut manager = ConnectionManager::new(jar, 0x000104);
        manager.set_limits(ConnectionLimits {
            min_connection_time: Duration::from_millis(100),
            grace_period_until: None,
            bypass_localhost: false,
        });

        // Insert 1001 connections from different IPs
        for i in 0..1001 {
            let ip = Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8);
            manager.handle_connection_request(ip, &[11], || 0);
        }

        // Wait for connection ticks to become obsolete
        std::thread::sleep(Duration::from_millis(110));

        // Insert one more to trigger eviction of all previous ones
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        manager.handle_connection_request(ip, &[11], || 0);

        // After the sleep and one more insert, all the previous 1001 entries are obsolete and should be evicted,
        // leaving only the 1 new entry.
        assert_eq!(manager.last_connection_ticks.len(), 1);
    }
}
