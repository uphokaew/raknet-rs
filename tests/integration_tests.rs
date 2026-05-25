use std::net::Ipv4Addr;
use std::time::Duration;
use raknet_rs::{
    decrypt, encrypt, CookieJar, ConnectionManager, ConnectionLimits, HandshakeResult,
    SAMP_PETARDED, OMP_PETARDED,
};

#[test]
fn test_integration_connection_handshake_samp() {
    let jar = CookieJar::new_seeded();
    let mut server_conn_mgr = ConnectionManager::new(jar.clone(), 0x000104);

    // Set connection limits
    server_conn_mgr.set_limits(ConnectionLimits {
        min_connection_time: Duration::from_millis(100),
        grace_period_until: None,
        bypass_localhost: true,
    });

    let client_ip = Ipv4Addr::new(127, 0, 0, 1);
    let _server_port = 7777;

    // --- STEP 1: Client sends initial request without cookie ---
    // SA-MP initial connection request packet begins with ID_CONNECTION_REQUEST (11) and no cookie
    let client_req_1 = vec![11];
    let handshake_res_1 = server_conn_mgr.handle_connection_request(client_ip, &client_req_1, || 0);

    // Server must respond asking for a cookie
    let expected_cookie = jar.get_cookie(client_ip);
    assert_eq!(handshake_res_1, HandshakeResult::SendCookie(expected_cookie));

    // --- STEP 2: Client receives the cookie, computes XORed cookie for standard SA-MP ---
    let client_xor_cookie = expected_cookie ^ SAMP_PETARDED;
    let mut client_req_2 = vec![11];
    client_req_2.extend_from_slice(&client_xor_cookie.to_le_bytes());

    // --- STEP 3: Client sends connection request with XORed cookie ---
    let handshake_res_2 = server_conn_mgr.handle_connection_request(client_ip, &client_req_2, || 0);

    // Server must accept the connection as standard SA-MP
    assert_eq!(handshake_res_2, HandshakeResult::AcceptSAMP);
}

#[test]
fn test_integration_connection_handshake_omp() {
    let jar = CookieJar::new_seeded();
    let omp_version = 0x000104; // v0.1.4
    let mut server_conn_mgr = ConnectionManager::new(jar.clone(), omp_version);

    let client_ip = Ipv4Addr::new(192, 168, 56, 10);
    let _server_port = 7777;

    // --- STEP 1: Client sends initial request, gets cookie challenge ---
    let client_req_1 = vec![11];
    let handshake_res_1 = server_conn_mgr.handle_connection_request(client_ip, &client_req_1, || 0);
    let expected_cookie = jar.get_cookie(client_ip);
    assert_eq!(handshake_res_1, HandshakeResult::SendCookie(expected_cookie));

    // --- STEP 2: Client computes OMP cookie response ---
    let client_xor_cookie = expected_cookie ^ OMP_PETARDED;
    let mut client_req_2 = vec![11];
    client_req_2.extend_from_slice(&client_xor_cookie.to_le_bytes());

    // --- STEP 3: Client sends connection request with OMP cookie ---
    // Server generates a random 32-bit encryption key (e.g. 0xABAB1212)
    let generated_key = 0xABAB1212;
    let handshake_res_2 = server_conn_mgr.handle_connection_request(client_ip, &client_req_2, || generated_key);

    // Server must accept as open.mp client and return the correct encryption key
    assert_eq!(
        handshake_res_2,
        HandshakeResult::AcceptOMP {
            encryption_key: generated_key,
            version: omp_version
        }
    );
}

#[test]
fn test_integration_crypto_communication() {
    // Standard server setup
    let port = 7777;
    let encryption_key = 0xDEADC0DE;
    let raw_payload = b"Important game synchronization RPC updates";

    // --- Server-to-Client Encryption (using OMP Player Key) ---
    let encrypted_server_packet = encrypt(raw_payload, encryption_key);
    assert_eq!(encrypted_server_packet.len(), raw_payload.len() + 1);

    // Client decrypts: XORing payload with key bytes
    let key_bytes = encryption_key.to_le_bytes();
    let client_decrypted_payload: Vec<u8> = encrypted_server_packet[1..]
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % 4])
        .collect();

    assert_eq!(client_decrypted_payload, raw_payload);

    // Verify server-side checksum calculation on client
    let mut expected_checksum = 0u8;
    for &b in raw_payload {
        expected_checksum ^= b & 0xAA;
    }
    assert_eq!(encrypted_server_packet[0], expected_checksum);

    // --- Client-to-Server Encryption (using custom substitution table) ---
    // Let's verify standard client-to-server decryption using `decrypt`
    let target_client_payload = b"Client keystroke sync updates";
    let port_mask = (port ^ 0xCC) as u8;

    // Simulate client-side encryption (doing custom reverse lookup in DECRYPT_KEY_TABLE)
    let mut client_encrypted_data = vec![0u8; target_client_payload.len() + 1];
    let mut checksum = 0u8;
    for (i, &b) in target_client_payload.iter().enumerate() {
        checksum ^= b & 0xAA;
        // Find index of byte in DECRYPT_KEY_TABLE
        let table_index = raknet_rs::DECRYPT_KEY_TABLE
            .iter()
            .position(|&x| x == b)
            .unwrap() as u8;
        
        let mut encrypted_byte = table_index;
        let byte_pos = i + 1; // 1-indexed for alternation check
        if (byte_pos & 1) == 0 {
            encrypted_byte ^= port_mask;
        }
        client_encrypted_data[byte_pos] = encrypted_byte;
    }
    client_encrypted_data[0] = checksum;

    // Server decrypts the client packet
    let server_decrypted_payload = decrypt(&client_encrypted_data, port)
        .expect("Server failed to decrypt client packet");

    assert_eq!(server_decrypted_payload, target_client_payload);
}

#[test]
fn test_integration_rpc_serialization() {
    use raknet_rs::BitStream;

    let id_rpc: u8 = 20; // ID_RPC constant
    let rpc_id: u8 = 42; // Example RPC ID (e.g. ShowPlayerDialog)
    let payload_data = vec![0x11, 0x22, 0x33, 0x44];

    // --- 1. Serialize RPC Packet ---
    let mut write_stream = BitStream::new();
    write_stream.write(&id_rpc);
    write_stream.write(&rpc_id);

    let num_bits = (payload_data.len() * 8) as u32;
    write_stream.write_compressed(&num_bits, true);
    write_stream.write_bytes(&payload_data);

    // --- 2. Deserialize RPC Packet ---
    let serialized_data = write_stream.as_bytes();
    let mut read_stream = BitStream::from_slice(serialized_data);

    let parsed_id_rpc = read_stream.read::<u8>().expect("Failed to read ID_RPC");
    let parsed_rpc_id = read_stream.read::<u8>().expect("Failed to read RPC ID");
    let parsed_bits_len = read_stream.read_compressed::<u32>(true).expect("Failed to read bits length");
    let parsed_payload = read_stream.read_bytes((parsed_bits_len / 8) as usize).expect("Failed to read payload data");

    // --- 3. Verify Integrity ---
    assert_eq!(parsed_id_rpc, id_rpc);
    assert_eq!(parsed_rpc_id, rpc_id);
    assert_eq!(parsed_bits_len, num_bits);
    assert_eq!(parsed_payload, payload_data);
}

