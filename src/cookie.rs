//! Connection verification cookies (Anti-DOS protection) for SA-MP/open.mp connections.
//!
//! Exposes the cookie generation algorithm that computes a validation cookie
//! from a client's IP address.

use std::net::Ipv4Addr;
use rand::Rng;

/// Stores and seeds the connection cookie matrix used for DOS protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieJar {
    /// The 2x256 table of 16-bit random cookies.
    pub cookies: [[u16; 256]; 2],
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieJar {
    /// Creates a new `CookieJar` with zeroed matrices.
    ///
    /// You must call `seed()` to populate it with secure random values.
    pub fn new() -> Self {
        Self {
            cookies: [[0u16; 256]; 2],
        }
    }

    /// Creates a new `CookieJar` seeded using thread-local RNG.
    ///
    /// # Examples
    ///
    /// ```
    /// use raknet_rs::CookieJar;
    ///
    /// let jar = CookieJar::new_seeded();
    /// ```
    pub fn new_seeded() -> Self {
        let mut jar = Self::new();
        jar.seed();
        jar
    }

    /// Seeds (or re-seeds) the cookie matrix with secure random 16-bit values.
    pub fn seed(&mut self) {
        let mut rng = rand::thread_rng();
        for i in 0..256 {
            self.cookies[0][i] = rng.gen_range(0..=u16::MAX);
            self.cookies[1][i] = rng.gen_range(0..=u16::MAX);
        }
    }

    /// Computes the connection cookie for the given IPv4 address.
    ///
    /// The calculation matches the byte pointer cast logic used by the C++ implementation:
    /// `(cookies[0][byte0] | cookies[1][byte3] << 8) ^ ((byte1 << 8) | byte2)`
    /// where `byte0..byte3` represent memory layout on little-endian platforms.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use raknet_rs::CookieJar;
    ///
    /// let jar = CookieJar::new_seeded();
    /// let ip = Ipv4Addr::new(127, 0, 0, 1);
    /// let cookie = jar.get_cookie(ip);
    /// ```
    ///
    /// # Arguments
    /// * `ip` - The IPv4 address of the client requesting connection.
    ///
    /// # Returns
    /// A `u16` connection cookie.
    pub fn get_cookie(&self, ip: Ipv4Addr) -> u16 {
        let octets = ip.octets();
        // C++ representation: const uint8_t* addressSplit = (const uint8_t*)&address;
        // On x86/x64 little-endian platforms, a uint32_t address of 127.0.0.1 (0x0100007f in host-order)
        // is stored as bytes [127, 0, 0, 1] in memory.
        // Therefore:
        // addressSplit[0] = octets[0] (127)
        // addressSplit[1] = octets[1] (0)
        // addressSplit[2] = octets[2] (0)
        // addressSplit[3] = octets[3] (1)
        let byte0 = octets[0] as usize;
        let byte1 = octets[1] as u16;
        let byte2 = octets[2] as u16;
        let byte3 = octets[3] as usize;

        let term1 = self.cookies[0][byte0] | (self.cookies[1][byte3] << 8);
        let term2 = (byte1 << 8) | byte2;

        term1 ^ term2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation_consistency() {
        let mut jar = CookieJar::new();
        // Seed with predictable values for testing
        for i in 0..256 {
            jar.cookies[0][i] = i as u16;
            jar.cookies[1][i] = (255 - i) as u16;
        }

        let ip1 = Ipv4Addr::new(127, 0, 0, 1);
        let cookie1 = jar.get_cookie(ip1);

        // Calculations manually:
        // byte0 = 127, byte1 = 0, byte2 = 0, byte3 = 1
        // term1 = cookies[0][127] | (cookies[1][1] << 8) = 127 | (254 << 8) = 127 | 65024 = 65151
        // term2 = (0 << 8) | 0 = 0
        // term1 ^ term2 = 65151 ^ 0 = 65151
        assert_eq!(cookie1, 65151);

        let ip2 = Ipv4Addr::new(192, 168, 1, 50);
        let cookie2 = jar.get_cookie(ip2);
        // byte0 = 192, byte1 = 168, byte2 = 1, byte3 = 50
        // term1 = cookies[0][192] | (cookies[1][50] << 8) = 192 | ((255 - 50) << 8) = 192 | (205 << 8) = 192 | 52480 = 52672
        // term2 = (168 << 8) | 1 = 43008 | 1 = 43009
                // term1 ^ term2 = 52672 ^ 43009 = 26049
        assert_eq!(cookie2, 26049);
    }

    #[test]
    fn test_seeding_uniqueness() {
        let jar1 = CookieJar::new_seeded();
        let jar2 = CookieJar::new_seeded();
        // Since seeding uses secure random values, the jars should be different
        assert_ne!(jar1, jar2);
    }
}
