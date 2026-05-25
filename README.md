# raknet-rs 🦀

Modern Rust implementation of the modified RakNet 2.52 network protocol extensions used in SA-MP (San Andreas Multiplayer) and open.mp.

This library is a pure Rust rewrite of the C++ `SAMPRakNet` extensions, providing 100% binary compatibility, memory safety, high performance, and ease of maintenance. It is designed to be integrated into any standard Rust-based UDP/RakNet engine.

---

## ฟีเจอร์ที่รองรับ (Features)

- **`crypto` (Cryptography)**: ระบบเข้ารหัสและถอดรหัสของ SA-MP/open.mp:
  - **Client-to-Server Decryption**: ถอดรหัสผ่าน Substitution Cipher Table แบบ 256 ไบต์สลับ XOR ตามค่า Port
  - **Server-to-Client Encryption**: เข้ารหัสด้วยคีย์ผู้เล่น 32 บิต เฉพาะทางสำหรับ open.mp
- **`auth` (Authentication Challenge)**: ระบบท้าทายการยืนยันตัวตนสำหรับไคลเอนต์ (`AUTH_TABLE` 256 คู่ ดั้งเดิมตาม C++ ต้นฉบับ)
- **`cookie` (Anti-DOS Cookies)**: การสร้าง Connection Cookie จาก IP เพื่อยืนยันคำขอเชื่อมต่อจริง (คำนวณแบบ Little-Endian ของ C++ เสมอ)
- **`bitstream` (Bit-aligned Serializer)**: ระบบช่วยเขียนและอ่านข้อมูลระดับบิต (`BitStream`) รวมถึงกลไกการบีบอัดแบบประหยัดบิตของ RakNet (`WriteCompressed` / `ReadCompressed`)
- **`query` (UDP Server Query)**: ตัววิเคราะห์และสร้างข้อมูลตอบกลับของ UDP Query Protocol ของ SA-MP (`Info`, `Players`, `Rules`, `Extra Info`, `Ping`, `RCON`)
- **`conn` (Handshake Manager)**: ตัวช่วยควบคุมระบบตรวจสอบความถี่ (Limits) และควบคุมขั้นตอนขอเชื่อมต่อ (Handshake flow)

---

## วิธีการนำไปใช้งาน (How to Use & Integrate)

หากต้องการนำ `raknet-rs` ไปทำเซิร์ฟเวอร์หรือไคลเอนต์ใหม่ด้วย Rust คุณสามารถประยุกต์ใช้โมดูลต่าง ๆ ร่วมกับช่องทาง Socket UDP ได้ดังนี้:

### 1. การจัดการตอนรับส่งข้อมูลทางเครือข่ายดิบ (Crypto Integration)
ในส่วนของ Network Loop ที่รับส่ง UDP Datagrams:

```rust
use std::net::UdpSocket;
use raknet_rs::crypto::{decrypt, encrypt};

fn handle_incoming_datagram(socket: &UdpSocket, buf: &[u8], client_addr: std::net::SocketAddr, server_port: u16) {
    // 1. ถอดรหัสแพ็กเกจที่รับมาจากไคลเอนต์ทันที
    if let Some(decrypted_payload) = decrypt(buf, server_port) {
        // 2. นำ decrypted_payload ไปประมวลผลต่อในส่วนของ Reliability Layer (ACKs, Sequence, etc.)
    } else {
        // ตัดแพ็กเกจทิ้งเนื่องจาก Checksum หรือโครงสร้างไม่ถูกต้อง
    }
}
```

### 2. ขั้นตอนการตรวจสอบสิทธิ์เชื่อมต่อ (Handshake Flow)
ใช้ `ConnectionManager` จัดการแลกเปลี่ยน Cookie และตรวจประเภทไคลเอนต์:

```rust
use std::net::Ipv4Addr;
use raknet_rs::{ConnectionManager, CookieJar, HandshakeResult};

let jar = CookieJar::new_seeded();
let mut conn_manager = ConnectionManager::new(jar, 0x000104); // ใส่ OMP Version ปัจจุบัน

// เมื่อมีแพ็กเกจเชื่อมต่อ (ID_CONNECTION_REQUEST) ส่งเข้ามา:
let client_ip = Ipv4Addr::new(127, 0, 0, 1);
let payload = &[11, 0x34, 0x56]; // แพ็กเกจจำลอง

match conn_manager.handle_connection_request(client_ip, payload, || rand::random::<u32>()) {
    HandshakeResult::SendCookie(cookie_val) => {
        // ส่งข้อความคุกกี้กลับไปให้ไคลเอนต์ (ID_OPEN_CONNECTION_COOKIE + cookie_val)
    }
    HandshakeResult::AcceptSAMP => {
        // ไคลเอนต์เป็น SA-MP ปกติ -> อนุญาตและทำการตอบรับการเชื่อมต่อ
    }
    HandshakeResult::AcceptOMP { encryption_key, version } => {
        // ไคลเอนต์เป็น open.mp -> ตอบรับและบันทึกคีย์เข้ารหัสผู้เล่น (encryption_key) เพื่อส่งข้อมูลกลับ
    }
    HandshakeResult::Rejected(reason) => {
        // ปฏิเสธการเชื่อมต่อ (เช่น โดนจำกัดความถี่หรือกำลังอยู่ในกระบวนการขอเชื่อมต่ออยู่แล้ว)
    }
}
```

### 3. การใช้งาน BitStream ในการเขียน/อ่าน RPC
ถอดและใส่ข้อมูลแบบเดียวกับ C++ BitStream:

```rust
use raknet_rs::BitStream;

// ตัวอย่างการประกอบแพ็กเกจ RPC ส่งกลับหาผู้เล่น
let mut bs = BitStream::new();
let id_rpc: u8 = 20; // ID_RPC
let rpc_id: u8 = 42; // RPC ID เช่น ShowPlayerDialog
bs.write(&id_rpc);
bs.write(&rpc_id);

// เขียนขนาดพารามิเตอร์แบบบีบอัด (WriteCompressed)
let rpc_data = vec![0x11, 0x22, 0x33, 0x44];
let num_bits = (rpc_data.len() * 8) as u32;
bs.write_compressed(&num_bits, true);
bs.write_bytes(&rpc_data);

let packet_to_send = bs.as_bytes(); // ข้อมูลไบนารีพร้อมส่ง
```

### 4. การจัดการแพ็กเกจเซิฟเวอร์สอบถาม (SAMP Query Handler)
วิเคราะห์และตอบกลับแพ็กเกจคำร้องเรียน Query:

```rust
use raknet_rs::{QueryPacket, QueryPayload};

fn handle_query(raw_data: &[u8]) {
    if let Ok(packet) = QueryPacket::parse(raw_data, false) {
        match packet.payload {
            QueryPayload::Ping(token) => {
                // ตอบกลับด้วยชุดข้อมูลเดิมทันที
            }
            QueryPayload::Info { .. } => {
                // ประกอบข้อมูลห้องส่งกลับผ่าน QueryPayload::Info
            }
            _ => {}
        }
    }
}
```

---

## การตรวจสอบความถูกต้อง (Testing)

คุณสามารถเปิดทดสอบความเข้ากันได้และการประมวลผลทั้งหมดได้ทันทีโดยสั่งคำสั่ง:

```bash
cargo test
```
