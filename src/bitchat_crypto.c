/*
 * bitchat Cryptography Implementation
 * Full Noise_XX_25519_ChaChaPoly_SHA256 Protocol
 * Using PSA Crypto API (mbedTLS 3.x)
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <psa/crypto.h>
#include <string.h>

#include "bitchat_protocol.h"

LOG_MODULE_REGISTER(bitchat_crypto, LOG_LEVEL_INF);

/* External mutex for serializing UART output (defined in main.c) */
extern struct k_mutex uart_mutex;

#define NOISE_PROTOCOL_NAME "Noise_XX_25519_ChaChaPoly_SHA256"

/* ========== Key Generation ========== */

int bitchat_generate_keypair(uint8_t *private_key, uint8_t *public_key)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	uint8_t public_key_buffer[32]; /* Raw 32-byte Curve25519 public key */
	size_t public_key_len;
	size_t private_key_len;
	
	/* Configure key for ECDH on Curve25519 (X25519) */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attributes, 255);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	
	status = psa_generate_key(&attributes, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to generate keypair: %d", status);
		return -1;
	}
	
	status = psa_export_key(key_id, private_key, NOISE_KEY_SIZE, &private_key_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export private key: %d", status);
		psa_destroy_key(key_id);
		return -1;
	}
	
	status = psa_export_public_key(key_id, public_key_buffer, sizeof(public_key_buffer), 
	                               &public_key_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export public key: %d", status);
		psa_destroy_key(key_id);
		return -1;
	}
	
	/* Curve25519 public key is raw 32 bytes (no prefix) */
	memcpy(public_key, public_key_buffer, NOISE_KEY_SIZE);
	
	psa_destroy_key(key_id);
	return 0;
}

/* ========== ECDH (Diffie-Hellman) ========== */

int bitchat_ecdh(const uint8_t *our_private, const uint8_t *their_public, 
                 uint8_t *shared_secret)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	size_t shared_secret_len;
	
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attributes, 255);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	
	status = psa_import_key(&attributes, our_private, NOISE_KEY_SIZE, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to import private key: %d", status);
		return -1;
	}
	
	/* Curve25519 public key is raw 32 bytes (no prefix) */
	status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id, their_public, NOISE_KEY_SIZE,
	                               shared_secret, NOISE_KEY_SIZE, &shared_secret_len);
	
	psa_destroy_key(key_id);
	
	if (status != PSA_SUCCESS) {
		LOG_ERR("ECDH failed: %d", status);
		return -1;
	}
	
	return 0;
}

/* ========== Crypto Primitives ========== */

int bitchat_sha256(const uint8_t *data, size_t len, uint8_t *hash)
{
	psa_status_t status;
	size_t hash_len;
	
	status = psa_hash_compute(PSA_ALG_SHA_256, data, len, hash, NOISE_HASH_SIZE, &hash_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("SHA256 failed: %d", status);
		return -1;
	}
	return 0;
}

/* Simplified HKDF for Noise MixKey */
static int noise_hkdf(const uint8_t *ck, const uint8_t *ikm, size_t ikm_len,
                      uint8_t *out1, uint8_t *out2)
{
	uint8_t temp_key[NOISE_HASH_SIZE];
	uint8_t info1[NOISE_HASH_SIZE + 1];
	uint8_t info2[NOISE_HASH_SIZE + 1];
	
	/* HMAC-SHA256(ck, ikm) -> temp_key */
	psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	size_t mac_len;
	
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attr, 256);
	
	if (psa_import_key(&attr, ck, NOISE_HASH_SIZE, &key_id) != PSA_SUCCESS) {
		return -1;
	}
	
	if (psa_mac_compute(key_id, alg, ikm, ikm_len, temp_key, 
	                    NOISE_HASH_SIZE, &mac_len) != PSA_SUCCESS) {
		psa_destroy_key(key_id);
		return -1;
	}
	psa_destroy_key(key_id);
	
	/* Derive output1: HMAC(temp_key, 0x01) */
	info1[0] = 0x01;
	if (psa_import_key(&attr, temp_key, NOISE_HASH_SIZE, &key_id) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_mac_compute(key_id, alg, info1, 1, out1, NOISE_HASH_SIZE, &mac_len) != PSA_SUCCESS) {
		psa_destroy_key(key_id);
		return -1;
	}
	
	/* Derive output2: HMAC(temp_key, out1 || 0x02) */
	memcpy(info2, out1, NOISE_HASH_SIZE);
	info2[NOISE_HASH_SIZE] = 0x02;
	if (psa_mac_compute(key_id, alg, info2, NOISE_HASH_SIZE + 1, 
	                    out2, NOISE_HASH_SIZE, &mac_len) != PSA_SUCCESS) {
		psa_destroy_key(key_id);
		return -1;
	}
	psa_destroy_key(key_id);
	
	return 0;
}

/* ========== Noise Protocol Functions ========== */

void noise_mix_hash(uint8_t *h, const uint8_t *data, size_t len)
{
	uint8_t temp[NOISE_HASH_SIZE + 512];
	size_t total_len = NOISE_HASH_SIZE + len;
	
	if (total_len > sizeof(temp)) {
		LOG_ERR("Data too large for mix_hash");
		return;
	}
	
	memcpy(temp, h, NOISE_HASH_SIZE);
	memcpy(temp + NOISE_HASH_SIZE, data, len);
	bitchat_sha256(temp, total_len, h);
}

void noise_mix_key(uint8_t *ck, uint8_t *k, const uint8_t *ikm, size_t len)
{
	uint8_t temp_ck[NOISE_HASH_SIZE];
	uint8_t temp_k[NOISE_HASH_SIZE];
	
	if (noise_hkdf(ck, ikm, len, temp_ck, temp_k) == 0) {
		memcpy(ck, temp_ck, NOISE_HASH_SIZE);
		if (k) {
			memcpy(k, temp_k, NOISE_KEY_SIZE);
		}
	}
}

/* ChaCha20-Poly1305 encryption for Noise protocol */
int noise_encrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len,
                  const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t *ciphertext, uint8_t *tag)
{
	psa_status_t status;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	uint8_t nonce_bytes[12] = {0};
	size_t output_len;
	uint8_t temp_output[512];
	
	if (plaintext_len + 16 > sizeof(temp_output)) {
		LOG_ERR("Plaintext too large for encryption");
		return -1;
	}
	
	/* Encode nonce as 12 bytes (little-endian, lower 8 bytes starting at offset 4) */
	memcpy(nonce_bytes + 4, &nonce, sizeof(nonce));
	
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
	psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&attr, 256);
	
	status = psa_import_key(&attr, key, NOISE_KEY_SIZE, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to import encryption key: %d", status);
		return -1;
	}
	
	status = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305, nonce_bytes, 12, ad, ad_len,
	                          plaintext, plaintext_len, temp_output, 
	                          plaintext_len + 16, &output_len);
	
	psa_destroy_key(key_id);
	
	if (status != PSA_SUCCESS) {
		LOG_ERR("ChaCha20-Poly1305 encryption failed: %d", status);
		return -1;
	}
	
	/* Split output into ciphertext and tag */
	memcpy(ciphertext, temp_output, plaintext_len);
	memcpy(tag, temp_output + plaintext_len, 16);
	
	return 0;
}

int noise_decrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *tag, uint8_t *plaintext)
{
	psa_status_t status;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	uint8_t nonce_bytes[12] = {0};
	uint8_t ct_with_tag[512];
	size_t output_len;
	
	if (ciphertext_len + 16 > sizeof(ct_with_tag)) {
		LOG_ERR("Ciphertext too large for decryption");
		return -1;
	}
	
	/* Encode nonce as 12 bytes (little-endian) */
	memcpy(nonce_bytes + 4, &nonce, sizeof(nonce));
	
	/* Combine ciphertext and tag for PSA AEAD */
	memcpy(ct_with_tag, ciphertext, ciphertext_len);
	memcpy(ct_with_tag + ciphertext_len, tag, 16);
	
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
	psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&attr, 256);
	
	status = psa_import_key(&attr, key, NOISE_KEY_SIZE, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to import decryption key: %d", status);
		return -1;
	}
	
	status = psa_aead_decrypt(key_id, PSA_ALG_CHACHA20_POLY1305, nonce_bytes, 12, ad, ad_len,
	                          ct_with_tag, ciphertext_len + 16, plaintext,
	                          ciphertext_len, &output_len);
	
	psa_destroy_key(key_id);
	
	if (status != PSA_SUCCESS) {
		LOG_ERR("ChaCha20-Poly1305 decryption failed: %d", status);
		return -1;
	}
	
	return 0;
}

/* ========== Noise XX Handshake ========== */

int noise_init_session(struct noise_session *session, bool initiator,
                       const struct bitchat_identity *identity)
{
	memset(session, 0, sizeof(*session));
	
	session->state = NOISE_INIT;
	
	/* Initialize h and ck with protocol name */
	const char *protocol = NOISE_PROTOCOL_NAME;
	bitchat_sha256((const uint8_t *)protocol, strlen(protocol), session->h);
	memcpy(session->ck, session->h, NOISE_HASH_SIZE);
	
	/* Generate ephemeral keypair */
	if (bitchat_generate_keypair(session->e_private, session->e_public) != 0) {
		return -1;
	}
	
	session->session_id = sys_rand16_get();
	session->last_activity = k_uptime_get();
	
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Noise session initialized (ID: 0x%04x, %s)", 
	        session->session_id, initiator ? "initiator" : "responder");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* ========== Noise XX Handshake - Message Processing ========== */

/* Message 1 (initiator -> responder): -> e */
int noise_handshake_write_message1(struct noise_session *session, uint8_t *out, size_t *out_len)
{
	if (session->state != NOISE_INIT) {
		LOG_ERR("Invalid state for message 1: %d", session->state);
		return -1;
	}
	
	/* Send: e */
	memcpy(out, session->e_public, NOISE_KEY_SIZE);
	*out_len = NOISE_KEY_SIZE;
	
	/* Update handshake hash: h = HASH(h || e) */
	noise_mix_hash(session->h, session->e_public, NOISE_KEY_SIZE);
	
	session->state = NOISE_SENT_E;
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Sent handshake message 1 (e)");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* Message 1 (responder receives): <- e */
int noise_handshake_read_message1(struct noise_session *session, const uint8_t *in, size_t in_len)
{
	if (session->state != NOISE_INIT) {
		LOG_ERR("Invalid state for reading message 1: %d", session->state);
		return -1;
	}
	
	if (in_len < NOISE_KEY_SIZE) {
		LOG_ERR("Message 1 too short: %zu", in_len);
		return -1;
	}
	
	/* Receive: e */
	memcpy(session->remote_e, in, NOISE_KEY_SIZE);
	
	/* Update handshake hash: h = HASH(h || e) */
	noise_mix_hash(session->h, session->remote_e, NOISE_KEY_SIZE);
	
	session->state = NOISE_SENT_E;  /* Ready to send message 2 */
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Received handshake message 1 (e)");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* Message 2 (responder -> initiator): -> e, ee, s, es */
int noise_handshake_write_message2(struct noise_session *session, 
                                   const struct bitchat_identity *identity,
                                   uint8_t *out, size_t *out_len)
{
	uint8_t dh_result[NOISE_KEY_SIZE];
	uint8_t k[NOISE_KEY_SIZE];
	uint8_t tag[16];
	size_t offset = 0;
	
	if (session->state != NOISE_SENT_E) {
		LOG_ERR("Invalid state for message 2: %d", session->state);
		return -1;
	}
	
	/* Send: e */
	memcpy(out + offset, session->e_public, NOISE_KEY_SIZE);
	offset += NOISE_KEY_SIZE;
	noise_mix_hash(session->h, session->e_public, NOISE_KEY_SIZE);
	
	/* Perform: ee */
	if (bitchat_ecdh(session->e_private, session->remote_e, dh_result) != 0) {
		LOG_ERR("ECDH ee failed");
		return -1;
	}
	noise_mix_key(session->ck, NULL, dh_result, NOISE_KEY_SIZE);
	
	/* Send: s (encrypted with tag) */
	noise_mix_key(session->ck, k, NULL, 0);  /* Derive temporary key */
	if (noise_encrypt(k, 0, session->h, NOISE_HASH_SIZE,
	                  identity->noise_public, NOISE_KEY_SIZE,
	                  out + offset, tag) != 0) {
		LOG_ERR("Failed to encrypt static key");
		return -1;
	}
	/* Copy ciphertext and tag to output */
	memcpy(out + offset + NOISE_KEY_SIZE, tag, 16);
	/* Update hash with ciphertext+tag */
	noise_mix_hash(session->h, out + offset, NOISE_KEY_SIZE + 16);
	offset += NOISE_KEY_SIZE + 16;
	
	/* Perform: es */
	if (bitchat_ecdh(identity->noise_private, session->remote_e, dh_result) != 0) {
		LOG_ERR("ECDH es failed");
		return -1;
	}
	noise_mix_key(session->ck, NULL, dh_result, NOISE_KEY_SIZE);
	
	*out_len = offset;
	session->state = NOISE_RECEIVED_EES_S_ES;
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Sent handshake message 2 (e, ee, s, es)");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* Message 2 (initiator receives): <- e, ee, s, es */
int noise_handshake_read_message2(struct noise_session *session,
                                  const struct bitchat_identity *identity,
                                  const uint8_t *in, size_t in_len)
{
	uint8_t dh_result[NOISE_KEY_SIZE];
	uint8_t k[NOISE_KEY_SIZE];
	uint8_t tag[16];
	size_t offset = 0;
	
	if (session->state != NOISE_SENT_E) {
		LOG_ERR("Invalid state for reading message 2: %d", session->state);
		return -1;
	}
	
	if (in_len < (NOISE_KEY_SIZE + NOISE_KEY_SIZE + 16)) {
		LOG_ERR("Message 2 too short: %zu (expected >= %d)", in_len, NOISE_KEY_SIZE + NOISE_KEY_SIZE + 16);
		return -1;
	}
	
	/* Receive: e */
	memcpy(session->remote_e, in + offset, NOISE_KEY_SIZE);
	offset += NOISE_KEY_SIZE;
	noise_mix_hash(session->h, session->remote_e, NOISE_KEY_SIZE);
	
	/* Perform: ee */
	if (bitchat_ecdh(session->e_private, session->remote_e, dh_result) != 0) {
		LOG_ERR("ECDH ee failed");
		return -1;
	}
	noise_mix_key(session->ck, NULL, dh_result, NOISE_KEY_SIZE);
	
	/* Receive: s (encrypted with tag) */
	noise_mix_key(session->ck, k, NULL, 0);  /* Derive temporary key */
	memcpy(tag, in + offset + NOISE_KEY_SIZE, 16);
	if (noise_decrypt(k, 0, session->h, NOISE_HASH_SIZE,
	                  in + offset, NOISE_KEY_SIZE, tag,
	                  session->remote_s) != 0) {
		LOG_ERR("Failed to decrypt static key");
		return -1;
	}
	/* Update hash with ciphertext+tag */
	noise_mix_hash(session->h, in + offset, NOISE_KEY_SIZE + 16);
	offset += NOISE_KEY_SIZE + 16;
	
	/* Perform: es */
	if (bitchat_ecdh(session->e_private, session->remote_s, dh_result) != 0) {
		LOG_ERR("ECDH es failed");
		return -1;
	}
	noise_mix_key(session->ck, NULL, dh_result, NOISE_KEY_SIZE);
	
	session->state = NOISE_RECEIVED_EES_S_ES;
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Received handshake message 2 (e, ee, s, es)");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* Message 3 (initiator -> responder): -> s, se */
int noise_handshake_write_message3(struct noise_session *session,
                                   const struct bitchat_identity *identity,
                                   uint8_t *out, size_t *out_len)
{
	uint8_t dh_result[NOISE_KEY_SIZE];
	uint8_t k[NOISE_KEY_SIZE];
	uint8_t tag[16];
	size_t offset = 0;
	
	if (session->state != NOISE_RECEIVED_EES_S_ES) {
		LOG_ERR("Invalid state for message 3: %d", session->state);
		return -1;
	}
	
	/* Send: s (encrypted with tag) */
	noise_mix_key(session->ck, k, NULL, 0);  /* Derive temporary key */
	if (noise_encrypt(k, 0, session->h, NOISE_HASH_SIZE,
	                  identity->noise_public, NOISE_KEY_SIZE,
	                  out + offset, tag) != 0) {
		LOG_ERR("Failed to encrypt static key");
		return -1;
	}
	/* Copy ciphertext and tag */
	memcpy(out + offset + NOISE_KEY_SIZE, tag, 16);
	/* Update hash with ciphertext+tag */
	noise_mix_hash(session->h, out + offset, NOISE_KEY_SIZE + 16);
	offset += NOISE_KEY_SIZE + 16;
	
	/* Perform: se */
	if (bitchat_ecdh(identity->noise_private, session->remote_e, dh_result) != 0) {
		LOG_ERR("ECDH se failed");
		return -1;
	}
	noise_mix_key(session->ck, NULL, dh_result, NOISE_KEY_SIZE);
	
	*out_len = offset;
	session->state = NOISE_SENT_S_SE;
	
	/* Derive transport keys */
	noise_mix_key(session->ck, session->tx_key, NULL, 0);
	noise_mix_key(session->ck, session->rx_key, NULL, 0);
	session->tx_nonce = 0;
	session->rx_nonce = 0;
	session->state = NOISE_TRANSPORT;
	
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Sent handshake message 3 (s, se) - transport mode");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* Message 3 (responder receives): <- s, se */
int noise_handshake_read_message3(struct noise_session *session,
                                  const uint8_t *in, size_t in_len)
{
	uint8_t dh_result[NOISE_KEY_SIZE];
	uint8_t k[NOISE_KEY_SIZE];
	uint8_t tag[16];
	size_t offset = 0;
	
	if (session->state != NOISE_RECEIVED_EES_S_ES) {
		LOG_ERR("Invalid state for reading message 3: %d", session->state);
		return -1;
	}
	
	if (in_len < (NOISE_KEY_SIZE + 16)) {
		LOG_ERR("Message 3 too short: %zu (expected >= %d)", in_len, NOISE_KEY_SIZE + 16);
		return -1;
	}
	
	/* Receive: s (encrypted with tag) */
	noise_mix_key(session->ck, k, NULL, 0);  /* Derive temporary key */
	memcpy(tag, in + offset + NOISE_KEY_SIZE, 16);
	if (noise_decrypt(k, 0, session->h, NOISE_HASH_SIZE,
	                  in + offset, NOISE_KEY_SIZE, tag,
	                  session->remote_s) != 0) {
		LOG_ERR("Failed to decrypt static key");
		return -1;
	}
	/* Update hash with ciphertext+tag */
	noise_mix_hash(session->h, in + offset, NOISE_KEY_SIZE + 16);
	offset += NOISE_KEY_SIZE + 16;
	
	/* Perform: se */
	if (bitchat_ecdh(session->e_private, session->remote_s, dh_result) != 0) {
		LOG_ERR("ECDH se failed");
		return -1;
	}
	noise_mix_key(session->ck, NULL, dh_result, NOISE_KEY_SIZE);
	
	/* Derive transport keys (note: swapped for responder) */
	noise_mix_key(session->ck, session->rx_key, NULL, 0);
	noise_mix_key(session->ck, session->tx_key, NULL, 0);
	session->tx_nonce = 0;
	session->rx_nonce = 0;
	session->state = NOISE_TRANSPORT;
	
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Received handshake message 3 (s, se) - transport mode");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* Transport encryption (after handshake complete) */
int noise_transport_encrypt(struct noise_session *session, const uint8_t *plaintext,
                            size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len)
{
	uint8_t tag[16];
	
	if (session->state != NOISE_TRANSPORT) {
		LOG_ERR("Not in transport mode");
		return -1;
	}
	
	if (noise_encrypt(session->tx_key, session->tx_nonce, NULL, 0,
	                  plaintext, plaintext_len, ciphertext, tag) != 0) {
		return -1;
	}
	
	memcpy(ciphertext + plaintext_len, tag, 16);
	*ciphertext_len = plaintext_len + 16;
	session->tx_nonce++;
	
	return 0;
}

int noise_transport_decrypt(struct noise_session *session, const uint8_t *ciphertext,
                            size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len)
{
	uint8_t tag[16];
	
	if (session->state != NOISE_TRANSPORT) {
		LOG_ERR("Not in transport mode");
		return -1;
	}
	
	if (ciphertext_len < 16) {
		LOG_ERR("Ciphertext too short");
		return -1;
	}
	
	size_t payload_len = ciphertext_len - 16;
	memcpy(tag, ciphertext + payload_len, 16);
	
	if (noise_decrypt(session->rx_key, session->rx_nonce, NULL, 0,
	                  ciphertext, payload_len, tag, plaintext) != 0) {
		return -1;
	}
	
	*plaintext_len = payload_len;
	session->rx_nonce++;
	
	return 0;
}

/* ========== Ephemeral-Only Handshake (BitChat Android Compatibility) ========== */

int noise_complete_ephemeral_handshake(struct noise_session *session, const uint8_t *remote_ephemeral)
{
	if (!session || !remote_ephemeral) {
		LOG_ERR("Invalid parameters");
		return -1;
	}
	
	/* Must be in NOISE_SENT_E state (after sending INIT) */
	if (session->state != NOISE_SENT_E) {
		LOG_ERR("Invalid state for ephemeral handshake: %d", session->state);
		return -1;
	}
	
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Completing ephemeral-only handshake (32-byte RESP mode)");
	k_mutex_unlock(&uart_mutex);
	
	/* Store remote ephemeral key */
	memcpy(session->remote_e, remote_ephemeral, NOISE_KEY_SIZE);
	
	/* Compute shared secret: DH(local_ephemeral, remote_ephemeral) */
	uint8_t shared_secret[NOISE_KEY_SIZE];
	if (bitchat_ecdh(session->e_private, remote_ephemeral, shared_secret) != 0) {
		LOG_ERR("DH operation failed");
		return -1;
	}
	
	/* Mix shared secret into chaining key using HKDF
	 * ck, temp_k = HKDF(ck, DH(e, e), 2)
	 */
	uint8_t temp_k1[NOISE_HASH_SIZE];
	uint8_t temp_k2[NOISE_HASH_SIZE];
	if (noise_hkdf(session->ck, shared_secret, NOISE_KEY_SIZE,
	               temp_k1, temp_k2) != 0) {
		LOG_ERR("HKDF failed");
		memset(shared_secret, 0, sizeof(shared_secret));
		return -1;
	}
	
	/* Update chaining key */
	memcpy(session->ck, temp_k1, NOISE_HASH_SIZE);
	
	/* Derive transport keys using split()
	 * temp_k1, temp_k2 = HKDF(ck, zero, 2)
	 * Split chaining key into send and receive keys
	 */
	uint8_t zero[1] = {0};
	if (noise_hkdf(session->ck, zero, 0,
	               session->tx_key, session->rx_key) != 0) {
		LOG_ERR("Transport key derivation failed");
		memset(shared_secret, 0, sizeof(shared_secret));
		memset(temp_k1, 0, sizeof(temp_k1));
		memset(temp_k2, 0, sizeof(temp_k2));
		return -1;
	}
	
	/* Initialize nonces */
	session->tx_nonce = 0;
	session->rx_nonce = 0;
	
	/* Update state to transport mode */
	session->state = NOISE_TRANSPORT;
	
	/* Clear sensitive material */
	memset(shared_secret, 0, sizeof(shared_secret));
	memset(temp_k1, 0, sizeof(temp_k1));
	memset(temp_k2, 0, sizeof(temp_k2));
	memset(session->e_private, 0, NOISE_KEY_SIZE); /* Clear ephemeral private key */
	
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Ephemeral-only handshake complete - TRANSPORT MODE ACTIVE");
	LOG_WRN("No static key authentication - forward secrecy only");
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

/* ========== Identity Initialization ========== */

int bitchat_init_identity(struct bitchat_identity *id, const char *nickname)
{
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Initializing bitchat identity...");
	k_mutex_unlock(&uart_mutex);
	
	if (bitchat_generate_keypair(id->noise_private, id->noise_public) != 0) {
		LOG_ERR("Failed to generate Noise keypair");
		return -1;
	}
	
	if (bitchat_generate_keypair(id->sign_private, id->sign_public) != 0) {
		LOG_ERR("Failed to generate signing keypair");
		return -1;
	}
	
	strncpy(id->nickname, nickname, bitchat_NICKNAME_LEN - 1);
	id->nickname[bitchat_NICKNAME_LEN - 1] = '\0';
	
	k_mutex_lock(&uart_mutex, K_FOREVER);
	LOG_INF("Identity: %s", id->nickname);
	LOG_INF("  Noise pub: %02x%02x...%02x%02x", 
	        id->noise_public[0], id->noise_public[1],
	        id->noise_public[30], id->noise_public[31]);
	k_mutex_unlock(&uart_mutex);
	
	return 0;
}

