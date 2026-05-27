//! SA-MP legacy UDP Query Protocol encoder and decoder.
//!
//! Handles building and parsing query packets ('i' - Info, 'c' - Players,
//! 'r' - Rules, 'o' - Extra Info, 'p' - Ping, 'x' - RCON).

use std::net::Ipv4Addr;
use std::io::{self, Cursor, Read, Write};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// The fixed size of the SA-MP query packet header.
pub const BASE_QUERY_SIZE: usize = 11;

/// SA-MP Query Signature: "SAMP"
pub const SAMP_SIGNATURE: &[u8; 4] = b"SAMP";

/// Errors that can occur during query packet parsing or serialization.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The signature does not match "SAMP".
    #[error("Invalid signature: expected 'SAMP', found {0:?}")]
    InvalidSignature(Vec<u8>),

    /// Packet is too small to contain a valid header.
    #[error("Packet size is too small: {0} bytes (minimum is 11)")]
    PacketTooSmall(usize),

    /// Invalid query opcode.
    #[error("Invalid opcode: '{0}'")]
    InvalidOpcode(char),

    /// UTF-8 decode error.
    #[error("Failed to parse string as UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// I/O error during reading/writing.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// The SA-MP query packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryHeader {
    /// Client or Server IPv4 address bytes.
    pub ip: Ipv4Addr,
    /// Server port.
    pub port: u16,
    /// Opcode character (e.g. 'i', 'c', 'r', 'o', 'p', 'x').
    pub opcode: u8,
}

impl QueryHeader {
    /// Reads a query header from a byte reader.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, QueryError> {
        Self::read_with_signature(reader, SAMP_SIGNATURE)
    }

    /// Reads a query header with a custom signature.
    pub fn read_with_signature<R: Read>(reader: &mut R, signature: &[u8; 4]) -> Result<Self, QueryError> {
        let mut sig = [0u8; 4];
        reader.read_exact(&mut sig)?;
        if &sig != signature {
            return Err(QueryError::InvalidSignature(sig.to_vec()));
        }

        let mut ip_bytes = [0u8; 4];
        reader.read_exact(&mut ip_bytes)?;
        let ip = Ipv4Addr::from(ip_bytes);
        
        let port = reader.read_u16::<LittleEndian>()?;
        let opcode = reader.read_u8()?;

        Ok(Self { ip, port, opcode })
    }

    /// Writes the query header to a byte writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write_with_signature(writer, SAMP_SIGNATURE)
    }

    /// Writes the query header with a custom signature.
    pub fn write_with_signature<W: Write>(&self, writer: &mut W, signature: &[u8; 4]) -> io::Result<()> {
        writer.write_all(signature)?;
        writer.write_all(&self.ip.octets())?;
        writer.write_u16::<LittleEndian>(self.port)?;
        writer.write_u8(self.opcode)?;
        Ok(())
    }
}

/// Player information returned in the 'c' (Players) query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPlayer {
    /// Player username.
    pub name: String,
    /// Player score.
    pub score: i32,
}

/// A parsed SA-MP query packet payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryPayload {
    /// Ping opcode ('p')
    Ping(u32),

    /// Info opcode ('i')
    Info {
        passworded: bool,
        players: u16,
        max_players: u16,
        hostname: String,
        gamemode: String,
        language: String,
    },

    /// Players opcode ('c')
    Players(Vec<QueryPlayer>),

    /// Rules opcode ('r')
    Rules(Vec<(String, String)>),

    /// Extra Info opcode ('o') - open.mp specific
    ExtraInfo {
        discord_link: String,
        light_banner_url: String,
        dark_banner_url: String,
        logo_url: String,
    },

    /// RCON request opcode ('x')
    RconRequest {
        password: String,
        command: String,
    },

    /// RCON response opcode ('x')
    RconResponse(String),
}

/// A complete query packet containing a header and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPacket {
    pub header: QueryHeader,
    pub payload: QueryPayload,
}

impl QueryPacket {
    /// Parses a raw query UDP packet.
    ///
    /// # Examples
    ///
    /// ```
    /// use raknet_rs::QueryPacket;
    ///
    /// let packet_bytes = b"SAMP\x7f\x00\x00\x01\x61\x1e\x70\x05\x00\x00\x00"; // Mock ping packet
    /// let parsed = QueryPacket::parse(packet_bytes, false);
    /// ```
    ///
    /// # Arguments
    /// * `data` - The raw UDP payload bytes.
    /// * `is_response` - True if parsing a server response, false for client requests.
    pub fn parse(data: &[u8], is_response: bool) -> Result<Self, QueryError> {
        Self::parse_with_signature(data, is_response, SAMP_SIGNATURE)
    }

    /// Parses a raw query UDP packet with a custom signature.
    pub fn parse_with_signature(data: &[u8], is_response: bool, signature: &[u8; 4]) -> Result<Self, QueryError> {
        if data.len() < BASE_QUERY_SIZE {
            return Err(QueryError::PacketTooSmall(data.len()));
        }

        let mut cursor = Cursor::new(data);
        let header = QueryHeader::read_with_signature(&mut cursor, signature)?;
        let payload = match header.opcode as char {
            'p' => {
                let token = cursor.read_u32::<LittleEndian>()?;
                QueryPayload::Ping(token)
            }
            'i' => {
                if is_response {
                    let passworded = cursor.read_u8()? != 0;
                    let players = cursor.read_u16::<LittleEndian>()?;
                    let max_players = cursor.read_u16::<LittleEndian>()?;
                    
                    let hostname = read_u32_str(&mut cursor)?;
                    let gamemode = read_u32_str(&mut cursor)?;
                    let language = read_u32_str(&mut cursor)?;

                    QueryPayload::Info {
                        passworded,
                        players,
                        max_players,
                        hostname,
                        gamemode,
                        language,
                    }
                } else {
                    QueryPayload::Info {
                        passworded: false,
                        players: 0,
                        max_players: 0,
                        hostname: String::new(),
                        gamemode: String::new(),
                        language: String::new(),
                    }
                }
            }
            'c' => {
                if is_response {
                    let count = cursor.read_u16::<LittleEndian>()?;
                    let remaining = cursor.get_ref().as_ref().len().saturating_sub(cursor.position() as usize);
                    let max_possible = remaining / 5; // Minimum size of player entry is 5 bytes
                    let capacity = std::cmp::min(count as usize, max_possible);
                    let mut players = Vec::with_capacity(capacity);
                    for _ in 0..count {
                        let name = read_u8_str(&mut cursor)?;
                        let score = cursor.read_i32::<LittleEndian>()?;
                        players.push(QueryPlayer { name, score });
                    }
                    QueryPayload::Players(players)
                } else {
                    QueryPayload::Players(vec![])
                }
            }
            'r' => {
                if is_response {
                    let count = cursor.read_u16::<LittleEndian>()?;
                    let remaining = cursor.get_ref().as_ref().len().saturating_sub(cursor.position() as usize);
                    let max_possible = remaining / 2; // Minimum size of rule entry is 2 bytes
                    let capacity = std::cmp::min(count as usize, max_possible);
                    let mut rules = Vec::with_capacity(capacity);
                    for _ in 0..count {
                        let name = read_u8_str(&mut cursor)?;
                        let value = read_u8_str(&mut cursor)?;
                        rules.push((name, value));
                    }
                    QueryPayload::Rules(rules)
                } else {
                    QueryPayload::Rules(vec![])
                }
            }
            'o' => {
                if is_response {
                    let discord_link = read_u32_str(&mut cursor)?;
                    let light_banner_url = read_u32_str(&mut cursor)?;
                    let dark_banner_url = read_u32_str(&mut cursor)?;
                    let logo_url = read_u32_str(&mut cursor)?;
                    QueryPayload::ExtraInfo {
                        discord_link,
                        light_banner_url,
                        dark_banner_url,
                        logo_url,
                    }
                } else {
                    QueryPayload::ExtraInfo {
                        discord_link: String::new(),
                        light_banner_url: String::new(),
                        dark_banner_url: String::new(),
                        logo_url: String::new(),
                    }
                }
            }
            'x' => {
                if is_response {
                    let msg = read_u16_str(&mut cursor)?;
                    QueryPayload::RconResponse(msg)
                } else {
                    let password = read_u16_str(&mut cursor)?;
                    let command = read_u16_str(&mut cursor)?;
                    QueryPayload::RconRequest { password, command }
                }
            }
            c => return Err(QueryError::InvalidOpcode(c)),
        };

        Ok(Self { header, payload })
    }

    /// Serializes this query packet to a byte vector.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use raknet_rs::{QueryPacket, QueryHeader, QueryPayload};
    ///
    /// let pkt = QueryPacket {
    ///     header: QueryHeader { ip: Ipv4Addr::new(127, 0, 0, 1), port: 7777, opcode: b'p' },
    ///     payload: QueryPayload::Ping(1234),
    /// };
    /// let bytes = pkt.serialize().unwrap();
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, QueryError> {
        self.serialize_with_signature(SAMP_SIGNATURE)
    }

    /// Serializes this query packet to a byte vector with a custom signature.
    pub fn serialize_with_signature(&self, signature: &[u8; 4]) -> Result<Vec<u8>, QueryError> {
        let mut buf = Vec::new();
        self.header.write_with_signature(&mut buf, signature)?;

        match &self.payload {
            QueryPayload::Ping(token) => {
                buf.write_u32::<LittleEndian>(*token)?;
            }
            QueryPayload::Info {
                passworded,
                players,
                max_players,
                hostname,
                gamemode,
                language,
            } => {
                buf.write_u8(*passworded as u8)?;
                buf.write_u16::<LittleEndian>(*players)?;
                buf.write_u16::<LittleEndian>(*max_players)?;
                write_u32_str(&mut buf, hostname)?;
                write_u32_str(&mut buf, gamemode)?;
                write_u32_str(&mut buf, language)?;
            }
            QueryPayload::Players(players) => {
                buf.write_u16::<LittleEndian>(players.len() as u16)?;
                for player in players {
                    write_u8_str(&mut buf, &player.name)?;
                    buf.write_i32::<LittleEndian>(player.score)?;
                }
            }
            QueryPayload::Rules(rules) => {
                buf.write_u16::<LittleEndian>(rules.len() as u16)?;
                for (name, val) in rules {
                    write_u8_str(&mut buf, name)?;
                    write_u8_str(&mut buf, val)?;
                }
            }
            QueryPayload::ExtraInfo {
                discord_link,
                light_banner_url,
                dark_banner_url,
                logo_url,
            } => {
                write_u32_str(&mut buf, discord_link)?;
                write_u32_str(&mut buf, light_banner_url)?;
                write_u32_str(&mut buf, dark_banner_url)?;
                write_u32_str(&mut buf, logo_url)?;
            }
            QueryPayload::RconRequest { password, command } => {
                write_u16_str(&mut buf, password)?;
                write_u16_str(&mut buf, command)?;
            }
            QueryPayload::RconResponse(msg) => {
                write_u16_str(&mut buf, msg)?;
            }
        }

        Ok(buf)
    }
}

// Helpers for reading string layouts

fn read_u8_str<T: AsRef<[u8]>>(reader: &mut Cursor<T>) -> Result<String, QueryError> {
    let len = reader.read_u8()? as usize;
    let remaining = reader.get_ref().as_ref().len().saturating_sub(reader.position() as usize);
    if len > remaining {
        return Err(QueryError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "string length exceeds remaining bytes")));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(crate::tis620::decode_tis620(&buf))
}

fn read_u16_str<T: AsRef<[u8]>>(reader: &mut Cursor<T>) -> Result<String, QueryError> {
    let len = reader.read_u16::<LittleEndian>()? as usize;
    let remaining = reader.get_ref().as_ref().len().saturating_sub(reader.position() as usize);
    if len > remaining {
        return Err(QueryError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "string length exceeds remaining bytes")));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(crate::tis620::decode_tis620(&buf))
}

fn read_u32_str<T: AsRef<[u8]>>(reader: &mut Cursor<T>) -> Result<String, QueryError> {
    let len = reader.read_u32::<LittleEndian>()? as usize;
    let remaining = reader.get_ref().as_ref().len().saturating_sub(reader.position() as usize);
    if len > remaining {
        return Err(QueryError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "string length exceeds remaining bytes")));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(crate::tis620::decode_tis620(&buf))
}

// Helpers for writing string layouts

fn write_u8_str<W: Write>(writer: &mut W, val: &str) -> io::Result<()> {
    let encoded = crate::tis620::encode_tis620(val);
    writer.write_u8(encoded.len() as u8)?;
    writer.write_all(&encoded)?;
    Ok(())
}

fn write_u16_str<W: Write>(writer: &mut W, val: &str) -> io::Result<()> {
    let encoded = crate::tis620::encode_tis620(val);
    writer.write_u16::<LittleEndian>(encoded.len() as u16)?;
    writer.write_all(&encoded)?;
    Ok(())
}

fn write_u32_str<W: Write>(writer: &mut W, val: &str) -> io::Result<()> {
    let encoded = crate::tis620::encode_tis620(val);
    writer.write_u32::<LittleEndian>(encoded.len() as u32)?;
    writer.write_all(&encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_header(opcode: char) -> QueryHeader {
        QueryHeader {
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port: 7777,
            opcode: opcode as u8,
        }
    }

    #[test]
    fn test_ping_serialization() {
        let p = QueryPacket {
            header: get_test_header('p'),
            payload: QueryPayload::Ping(1337),
        };

        let data = p.serialize().unwrap();
        assert_eq!(data.len(), BASE_QUERY_SIZE + 4);

        let parsed = QueryPacket::parse(&data, false).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_info_serialization() {
        let p = QueryPacket {
            header: get_test_header('i'),
            payload: QueryPayload::Info {
                passworded: true,
                players: 15,
                max_players: 100,
                hostname: "My Super Rust Server".to_string(),
                gamemode: "LVDM".to_string(),
                language: "Thai".to_string(),
            },
        };

        let data = p.serialize().unwrap();
        let parsed = QueryPacket::parse(&data, true).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_players_serialization() {
        let p = QueryPacket {
            header: get_test_header('c'),
            payload: QueryPayload::Players(vec![
                QueryPlayer { name: "Player1".to_string(), score: 500 },
                QueryPlayer { name: "Player2".to_string(), score: 0 },
            ]),
        };

        let data = p.serialize().unwrap();
        let parsed = QueryPacket::parse(&data, true).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_rules_serialization() {
        let p = QueryPacket {
            header: get_test_header('r'),
            payload: QueryPayload::Rules(vec![
                ("version".to_string(), "0.3.7".to_string()),
                ("weather".to_string(), "1".to_string()),
            ]),
        };

        let data = p.serialize().unwrap();
        let parsed = QueryPacket::parse(&data, true).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_extra_info_serialization() {
        let p = QueryPacket {
            header: get_test_header('o'),
            payload: QueryPayload::ExtraInfo {
                discord_link: "discord.gg/openmp".to_string(),
                light_banner_url: "https://example.com/light.png".to_string(),
                dark_banner_url: "https://example.com/dark.png".to_string(),
                logo_url: "https://example.com/logo.png".to_string(),
            },
        };

        let data = p.serialize().unwrap();
        let parsed = QueryPacket::parse(&data, true).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_rcon_request_serialization() {
        let p = QueryPacket {
            header: get_test_header('x'),
            payload: QueryPayload::RconRequest {
                password: "my_rcon_password".to_string(),
                command: "say Hello from Rust!".to_string(),
            },
        };

        let data = p.serialize().unwrap();
        let parsed = QueryPacket::parse(&data, false).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_rcon_response_serialization() {
        let p = QueryPacket {
            header: get_test_header('x'),
            payload: QueryPayload::RconResponse("All players kicked.".to_string()),
        };

        let data = p.serialize().unwrap();
        let parsed = QueryPacket::parse(&data, true).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn test_custom_signature_serialization() {
        let p = QueryPacket {
            header: get_test_header('i'),
            payload: QueryPayload::Info {
                passworded: false,
                players: 0,
                max_players: 100,
                hostname: "Rust Server".to_string(),
                gamemode: "CustomMode".to_string(),
                language: "Thai".to_string(),
            },
        };

        let custom_sig = b"RUST";
        let data = p.serialize_with_signature(custom_sig).unwrap();
        assert_eq!(&data[0..4], custom_sig);

        let parsed = QueryPacket::parse_with_signature(&data, true, custom_sig).unwrap();
        assert_eq!(parsed, p);

        // Parsing with standard SAMP signature must fail
        assert!(QueryPacket::parse_with_signature(&data, true, b"SAMP").is_err());
    }

    #[test]
    fn test_malicious_packets_bounds() {
        // Construct a query packet that pretends to have a huge hostname length (e.g. 4GB)
        let mut mal_packet = Vec::new();
        // SAMP header
        mal_packet.extend_from_slice(b"SAMP");
        mal_packet.extend_from_slice(&[127, 0, 0, 1]); // IP
        mal_packet.extend_from_slice(&7777u16.to_le_bytes()); // Port
        mal_packet.push(b'i'); // opcode 'i' (Info)
        
        // Info response payload
        mal_packet.push(1); // passworded
        mal_packet.extend_from_slice(&10u16.to_le_bytes()); // players
        mal_packet.extend_from_slice(&100u16.to_le_bytes()); // max players
        
        // Huge hostname string length (e.g. 4,000,000,000 bytes)
        mal_packet.extend_from_slice(&4_000_000_000u32.to_le_bytes());
        
        // Parsing this should fail cleanly returning an error instead of OOMing/panicking
        let parsed = QueryPacket::parse(&mal_packet, true);
        assert!(parsed.is_err());
    }
}
