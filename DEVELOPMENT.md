# raknet-rs Maintenance & Development Guide 🦀

คู่มือการพัฒนาโครงสร้างโค้ดและการทดสอบสำหรับนักพัฒนาและผู้ดูแลโปรเจกต์ `raknet-rs` เพื่อสนับสนุนการทำงานร่วมกันอย่างเป็นระบบ ปลอดภัย และดูแลรักษาง่ายในระยะยาว

---

## 1. โครงสร้างโปรเจกต์ (Project Directory Structure)

โปรเจกต์ได้รับการออกแบบตามสถาปัตยกรรมแบบ Modular โดยแยกโปรโตคอลเสริมของ RakNet 2.52 ใน SA-MP/open.mp ออกเป็นโมดูลย่อย ๆ:

```text
raknet-rs/
├── DEVELOPMENT.md   # คู่มือการทดสอบ โครงสร้าง และแนวทางการบำรุงรักษา (เอกสารนี้)
├── README.md        # แนะนำการใช้งานเบื้องต้นและตัวอย่างการทำ Integration
├── Cargo.toml       # กำหนด Dependencies และ Crate Metadata
├── src/
│   ├── lib.rs       # จุดเริ่มต้นของ Crate, กำหนดโมดูลย่อยและ Re-export APIs
│   ├── bitstream.rs # ระบบอ่าน/เขียนข้อมูลระดับบิตและการบีบอัด (BitStream)
│   ├── crypto.rs    # การเข้ารหัสและถอดรหัสแพ็กเกจ (Substitution + XOR)
│   ├── cookie.rs    # Anti-DOS Connection Cookie matrix
│   ├── auth.rs      # ระบบยืนยันตัวตนสำหรับไคลเอนต์ (AuthTable)
│   ├── conn.rs      # ตัวจัดการ Handshake (Connection Limits, Cookie verify)
│   ├── datagram.rs  # โครงสร้างชุดข้อมูลของ RakNet Datagram & InternalPacket
│   ├── query.rs     # ตัวประมวลผลเซิร์ฟเวอร์แบบตอบรับผ่าน UDP (SAMP Query)
│   └── tis620.rs    # ระบบแปลงรหัสอักขระภาษาไทย TIS-620 <-> UTF-8
└── tests/
    └── integration_tests.rs # การทดสอบจำลอง Handshake & Serialization แบบ End-to-End
```

---

## 2. กฎการออกแบบและการเขียนโค้ด (Coding & Architecture Standards)

เมื่อพัฒนาหรือเพิ่มเติมฟีเจอร์ใด ๆ ในอนาคต ให้ปฏิบัติตามกฎเหล็กดังต่อไปนี้:

### 2.1. Memory Safety & Unsafe
- หลีกเลี่ยงการใช้งาน `unsafe` บล็อก เว้นแต่จำเป็นต้องจัดการประสิทธิภาพหรือทำการแคสต์หน่วยความจำระดับต่ำ
- ฟังก์ชันใด ๆ ที่ใช้การแคสต์หน่วยความจำตรง ๆ เช่น การแปลงข้อมูลใน `BitStream` จะต้องได้รับการกรองประเภทด้วยตัวบ่งชี้ `SafeBufCast` เท่านั้น เพื่อป้องกันปัญหา Memory Leak หรือการเกิดพอยน์เตอร์พัง (Undefined Behavior)

### 2.2. Endian-Safe Coding (สถาปัตยกรรมหน่วยประมวลผล)
- ทุกแพ็กเกจในโปรโตคอล SA-MP/open.mp ใช้การจัดเรียงไบต์แบบ **Little-Endian**
- ห้ามทำการแคสต์ Raw pointer ของ IP Address หรือข้อมูลจำนวนเต็มบนหน่วยความจำโฮสต์ตรง ๆ แบบ C++ (`(const char*)&var`) เนื่องจากจะทำให้ค่าเปลี่ยนเมื่อทำงานบนบอร์ดที่เป็น Big-Endian (เช่น RISC หรือสถาปัตยกรรมเครือข่ายบางค่าย)
- ให้ใช้ `to_le_bytes()` หรืออินเทอร์เฟซ `byteorder` เสมอ เพื่อการแปลงข้อมูลที่เป็นอิสระจากสถาปัตยกรรมฮาร์ดแวร์

### 2.3. Zero-Allocation ใน Hot Paths
- ในโมดูลการเข้ารหัส (`crypto`) และการจัดการ Handshake จะถูกเรียกใช้งานบ่อยครั้งต่อวินาที (Hot paths) หลีกเลี่ยงการทำ Heap allocation (`Vec`, `String`) ใหม่ในแต่ละรอบหากไม่จำเป็น ให้ใช้ byte slices (`&[u8]`) ในการส่งผ่านข้อมูล

---

## 3. คู่มือการทดสอบ (Testing Guide)

การทดสอบในโปรเจกต์ `raknet-rs` แบ่งออกเป็น 2 ระดับหลัก:

### 3.1. Unit Tests (การทดสอบหน่วยย่อย)
อยู่ในส่วนท้ายสุดของแต่ละโมดูลย่อยใน `src/` (ภายใต้บล็อก `#[cfg(test)]`) โดยทดสอบตรรกะเฉพาะตัวของโมดูลนั้น ๆ เช่น:
- ทดสอบความเข้ากันได้ของการถอดรหัสและการเข้ารหัสใน `crypto.rs`
- ทดสอบการบีบอัดและเขียนบิตใน `bitstream.rs`

### 3.2. Integration Tests (การทดสอบระบบร่วม)
อยู่ในโฟลเดอร์ [tests/integration_tests.rs](file:///home/uphokaew/Desktop/samp/Rewrite/raknet-rs/tests/integration_tests.rs) ทำหน้าที่ทดสอบการทำงานตั้งแต่ต้นจนจบ (End-to-End Handshake Flow):
- จำลองการเข้าสู่ระบบแบบปกติของ SA-MP Client และการแลกเปลี่ยนคุกกี้
- จำลองการเข้าสู่ระบบแบบ open.mp Client และการสร้างคีย์ผู้เล่น
- จำลองการส่งข้อมูลแบบเข้ารหัสและการประกอบร่าง RPC ด้วย `BitStream`

### 3.3. คำสั่งสำหรับการรันทดสอบ (Running Tests)

สำหรับการรันชุดทดสอบทั้งหมดเพื่อเช็กความถูกต้อง:
```bash
# รันการทดสอบทั้งหมด (รวมถึง doc tests)
cargo test

# รันเฉพาะการทดสอบย่อยของโมดูลใดโมดูลหนึ่ง
cargo test crypto::tests

# รันด้วยโหมดตรวจสอบความครอบคลุม (หากมี cargo-tarpaulin ติดตั้งอยู่)
cargo tarpaulin
```

---

## 4. รายการตรวจสอบก่อนปล่อยเวอร์ชัน (Release Checklist)

ก่อนเปลี่ยนสถานะเป็นสาธารณะ (Public Release) หรืออัปเดตเวอร์ชันใหม่ทุกครั้ง:

1. **การตรวจสอบการทดสอบ**: ชุดคำสั่ง `cargo test` ต้องเป็นสีเขียว (Green) และผ่านการทดสอบครบ 100% ไม่มี Fail หรือ Ignored
2. **การสแกนความปลอดภัย**: รัน `cargo clippy --all-targets` และ `cargo audit` เพื่อหาข้อเตือนใจหรือช่องโหว่ในส่วน dependencies
3. **การตรวจสอบ API Documentation**: รัน `cargo doc --no-deps --open` เพื่อดูว่ามีรายละเอียดที่สะกดผิดหรือไม่มีเอกสารในส่วนที่เป็น public API หรือไม่
4. **ความมั่นคงของหน่วยความจำ**: ตรวจสอบว่าไม่มีโค้ดแคสต์โครงสร้างประเภทที่ไม่ใช่ POD (Plain Old Data) เข้ามาในฟังก์ชันของ `BitStream`
