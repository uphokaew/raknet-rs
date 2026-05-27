//! RakNet Datagram and Internal Packet serialization/deserialization.
//!
//! Compatible with RakNet 2.52 in RAKNET_LEGACY mode.

use crate::bitstream::BitStream;

/// Node representing a range of message/packet numbers for acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeNode {
    pub min: u16,
    pub max: u16,
}

/// A serialized list of Ranges used to send ACKs/NACKs in RakNet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeList {
    pub ranges: Vec<RangeNode>,
}

impl RangeList {
    /// Serializes the RangeList into the given BitStream.
    pub fn serialize(&self, bs: &mut BitStream) {
        let count = self.ranges.len() as u16;
        bs.write_compressed(&count, true);
        for range in &self.ranges {
            let single = range.min == range.max;
            bs.write_bit(single);
            bs.write(&range.min);
            if !single {
                bs.write(&range.max);
            }
        }
    }

    /// Deserializes a RangeList from the BitStream.
    pub fn deserialize(bs: &mut BitStream) -> Option<Self> {
        let count = bs.read_compressed::<u16>(true)?;
        let max_possible = bs.unread_bits() / 17; // Each range is at least 17 bits (1 bit single + 16 bits min)
        let capacity = std::cmp::min(count as usize, max_possible);
        let mut ranges = Vec::with_capacity(capacity);
        for _ in 0..count {
            let single = bs.read_bit()?;
            let min = bs.read::<u16>()?;
            let max = if single {
                min
            } else {
                bs.read::<u16>()?
            };
            ranges.push(RangeNode { min, max });
        }
        Some(Self { ranges })
    }
}

/// Reliability types supported by RakNet.
pub const UNRELIABLE: u8 = 6;
pub const UNRELIABLE_SEQUENCED: u8 = 7;
pub const RELIABLE: u8 = 8;
pub const RELIABLE_ORDERED: u8 = 9;
pub const RELIABLE_SEQUENCED: u8 = 10;

/// An internal packet encapsulated inside a RakNet Datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalPacket {
    pub message_number: u16,
    pub reliability: u8,
    pub ordering_channel: Option<u8>,
    pub ordering_index: Option<u16>,
    pub payload: Vec<u8>,
}

impl InternalPacket {
    /// Serializes the InternalPacket into the given BitStream.
    pub fn serialize(&self, bs: &mut BitStream) {
        // 1. Message Number (2 bytes)
        bs.write(&self.message_number);

        // 2. Reliability (4 bits in RAKNET_LEGACY)
        bs.write_bits(&[self.reliability], 4, true);

        // 3. Ordering channel and index (if reliability requires it)
        if self.reliability == UNRELIABLE_SEQUENCED
            || self.reliability == RELIABLE_ORDERED
            || self.reliability == RELIABLE_SEQUENCED
        {
            let channel = self.ordering_channel.unwrap_or(0);
            bs.write_bits(&[channel], 5, true);
            let index = self.ordering_index.unwrap_or(0);
            bs.write(&index);
        }

        // 4. Split packet (1 bit - false)
        bs.write_bit(false);

        // 5. Data length in bits (compressed u16)
        let bit_length = (self.payload.len() * 8) as u16;
        bs.write_compressed(&bit_length, true);

        // 6. Aligned data payload
        bs.write_aligned_bytes(&self.payload);
    }

    /// Deserializes an InternalPacket from the BitStream.
    pub fn deserialize(bs: &mut BitStream) -> Option<Self> {
        let message_number = bs.read::<u16>()?;
        let reliability = bs.read_bits(4, true)?[0];

        let mut ordering_channel = None;
        let mut ordering_index = None;

        if reliability == UNRELIABLE_SEQUENCED
            || reliability == RELIABLE_ORDERED
            || reliability == RELIABLE_SEQUENCED
        {
            ordering_channel = Some(bs.read_bits(5, true)?[0]);
            ordering_index = Some(bs.read::<u16>()?);
        }

        let is_split = bs.read_bit()?;
        if is_split {
            // Split packets are not supported in our simple handshake/chat server.
            let _split_id = bs.read::<u16>()?;
            let _split_index = bs.read_compressed::<u32>(true)?;
            let _split_count = bs.read_compressed::<u32>(true)?;
            return None;
        }

        let bit_length = bs.read_compressed::<u16>(true)?;
        let num_bytes = bit_length.div_ceil(8) as usize;
        let payload = bs.read_aligned_bytes(num_bytes)?;

        Some(Self {
            message_number,
            reliability,
            ordering_channel,
            ordering_index,
            payload,
        })
    }
}

/// A top-level UDP payload containing ACKs and/or Internal Packets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Datagram {
    pub has_acks: bool,
    pub acks: RangeList,
    pub packets: Vec<InternalPacket>,
}

impl Datagram {
    /// Serializes the entire Datagram into the given BitStream.
    pub fn serialize(&self, bs: &mut BitStream) {
        bs.write_bit(self.has_acks);
        if self.has_acks {
            self.acks.serialize(bs);
        }
        for packet in &self.packets {
            packet.serialize(bs);
        }
    }

    /// Deserializes a Datagram from the BitStream.
    pub fn deserialize(bs: &mut BitStream) -> Option<Self> {
        let has_acks = bs.read_bit()?;
        let mut acks = RangeList::default();
        if has_acks {
            acks = RangeList::deserialize(bs)?;
        }

        let mut packets = Vec::new();
        while bs.unread_bits() >= 16 {
            if let Some(packet) = InternalPacket::deserialize(bs) {
                packets.push(packet);
            } else {
                break;
            }
        }

        Some(Self {
            has_acks,
            acks,
            packets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rangelist_serialization() {
        let mut rl = RangeList::default();
        rl.ranges.push(RangeNode { min: 10, max: 10 });
        rl.ranges.push(RangeNode { min: 20, max: 25 });

        let mut bs = BitStream::new();
        rl.serialize(&mut bs);

        bs.reset_read_pointer();
        let decoded = RangeList::deserialize(&mut bs).unwrap();
        assert_eq!(decoded, rl);
    }

    #[test]
    fn test_internal_packet_serialization() {
        let pkt = InternalPacket {
            message_number: 42,
            reliability: RELIABLE_ORDERED,
            ordering_channel: Some(1),
            ordering_index: Some(5),
            payload: b"Hello".to_vec(),
        };

        let mut bs = BitStream::new();
        pkt.serialize(&mut bs);

        bs.reset_read_pointer();
        let decoded = InternalPacket::deserialize(&mut bs).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_datagram_serialization() {
        let mut dg = Datagram {
            has_acks: true,
            ..Default::default()
        };
        dg.acks.ranges.push(RangeNode { min: 1, max: 2 });
        dg.packets.push(InternalPacket {
            message_number: 100,
            reliability: RELIABLE,
            ordering_channel: None,
            ordering_index: None,
            payload: b"TestPayload".to_vec(),
        });

        let mut bs = BitStream::new();
        dg.serialize(&mut bs);

        bs.reset_read_pointer();
        let decoded = Datagram::deserialize(&mut bs).unwrap();
        assert_eq!(decoded, dg);
    }
}
