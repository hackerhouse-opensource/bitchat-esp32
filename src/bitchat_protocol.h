/*
 * bitchat Protocol Definitions
 * Based on Noise_XX_25519_ChaChaPoly_SHA256
 */

#ifndef bitchat_PROTOCOL_H
#define bitchat_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

/* Key sizes (bytes) */
#define NOISE_KEY_SIZE 32        /* X25519 / Ed25519 key size */
#define NOISE_HASH_SIZE 32       /* SHA-256 output */
#define NOISE_NONCE_SIZE 12      /* ChaCha20Poly1305 nonce */
#define NOISE_TAG_SIZE 16        /* Poly1305 authentication tag */

/* Packet constraints (bitchat spec) */
#define bitchat_PEER_ID_LEN 8    /* 8-byte truncated peer ID */
#define bitchat_MAX_TTL 7        /* Max hop count */
#define bitchat_NICKNAME_LEN 32
#define bitchat_SIGNATURE_LEN 64 /* Ed25519 signature */

/* Packet padding sizes (bitchat spec) */
#define bitchat_PADDED_SIZE_256   256
#define bitchat_PADDED_SIZE_512   512
#define bitchat_PADDED_SIZE_1024  1024
#define bitchat_PADDED_SIZE_2048  2048

/* Maximum payload before padding (2048 - header - IDs - signature) */
#define bitchat_MAX_PAYLOAD_SIZE  (bitchat_PADDED_SIZE_2048 - 13 - 16 - bitchat_SIGNATURE_LEN)

/* bitchat packet types (official BitChat protocol) */
enum bitchat_packet_type {
	bitchat_PKT_MESSAGE = 0x01,
	bitchat_PKT_DELIVERY_ACK = 0x02,
	bitchat_PKT_READ_RECEIPT = 0x03,
	/* Official BitChat uses single type 0x10 for all Noise handshake messages */
	bitchat_PKT_NOISE_HANDSHAKE = 0x10,  /* All handshake phases (INIT/RESP/FINISH) */
	/* Legacy aliases for backward compatibility - all map to 0x10 */
	bitchat_PKT_NOISE_HANDSHAKE_INIT = 0x10,
	bitchat_PKT_NOISE_HANDSHAKE_RESP = 0x10,
	bitchat_PKT_NOISE_HANDSHAKE_FINISH = 0x10,
	bitchat_PKT_NOISE_ENCRYPTED = 0x11,  /* Encrypted Noise transport messages */
	bitchat_PKT_FRAGMENT = 0x20,         /* Fragmented messages */
};

/* bitchat packet flags */
#define bitchat_FLAG_HAS_RECIPIENT  0x01
#define bitchat_FLAG_HAS_SIGNATURE  0x02
#define bitchat_FLAG_IS_COMPRESSED  0x04
#define bitchat_FLAG_IS_RELAY       0x08
#define bitchat_FLAG_IS_PRIVATE     0x10

/* Broadcast recipient ID (all 0xFF) */
#define bitchat_BROADCAST_ID 0xFFFFFFFFFFFFFFFFULL

/* TLV types for message payload encoding */
#define bitchat_TLV_NICKNAME      0x01  /* Nickname string */
#define bitchat_TLV_NOISE_INIT    0x02  /* Noise handshake ephemeral key (32 bytes) */
#define bitchat_TLV_NOISE_RESP    0x03  /* Noise handshake response (32-80 bytes: ephemeral or full) */
#define bitchat_TLV_NOISE_FINISH  0x04  /* Noise handshake finish (48 bytes: encrypted static + tag) */
#define bitchat_TLV_TEXT          0x05  /* Plain text message */
#define bitchat_TLV_ENCRYPTED     0x06  /* Encrypted content */
#define bitchat_TLV_CHANNEL       0x07  /* Channel name string */
#define bitchat_TLV_GEOHASH       0x08  /* Geohash identity string (for Nostr peer discovery) */
#define bitchat_TLV_PUBKEY        0x09  /* Nostr public key (32 bytes, for identity broadcasts) */

/* bitchat packet header (14 bytes fixed - official format) */
struct bitchat_header {
	uint8_t version;              /* Protocol version (1) */
	uint8_t type;                 /* Packet type */
	uint8_t ttl;                  /* Time-to-live (0-7) */
	uint64_t timestamp;           /* Unix timestamp (ms) - BIG ENDIAN */
	uint8_t flags;                /* Bitmask flags */
	uint16_t payload_len;         /* Payload length - BIG ENDIAN */
} __packed;

/* Full bitchat packet structure (padded to 256/512/1024/2048) */
struct bitchat_packet {
	struct bitchat_header header; /* 13 bytes */
	uint64_t sender_id;           /* 8 bytes - truncated SHA256(noise_public) */
	uint64_t recipient_id;        /* 8 bytes - optional, broadcast if 0xFF..FF */
	uint8_t payload[bitchat_MAX_PAYLOAD_SIZE];
	/* Note: signature (64 bytes) appended after payload if HAS_SIGNATURE flag set */
	/* Note: packet padded to 256/512/1024/2048 bytes with PKCS#7 style padding */
} __packed;

/* Fragment metadata for reassembly */
struct bitchat_fragment_info {
	uint16_t total_size;          /* Total message size */
	uint8_t fragment_count;       /* Total fragments */
	uint8_t fragment_index;       /* Current fragment (0-based) */
	uint32_t message_id;          /* Unique message ID for reassembly */
} __packed;

/* Noise handshake states */
enum noise_state {
	NOISE_INIT,
	NOISE_SENT_E,
	NOISE_RECEIVED_EES_S_ES,
	NOISE_SENT_S_SE,
	NOISE_TRANSPORT,
};

/* bitchat identity keypairs */
struct bitchat_identity {
	/* Noise static keypair (X25519 - DH key exchange) */
	uint8_t noise_private[NOISE_KEY_SIZE];
	uint8_t noise_public[NOISE_KEY_SIZE];
	
	/* Signing keypair (Ed25519 - authentication) */
	uint8_t sign_private[NOISE_KEY_SIZE];
	uint8_t sign_public[NOISE_KEY_SIZE];
	
	/* User nickname */
	char nickname[bitchat_NICKNAME_LEN];
};

/* Noise session state */
struct noise_session {
	enum noise_state state;
	
	/* Chaining key and handshake hash */
	uint8_t ck[NOISE_HASH_SIZE];
	uint8_t h[NOISE_HASH_SIZE];
	
	/* Local ephemeral keypair */
	uint8_t e_private[NOISE_KEY_SIZE];
	uint8_t e_public[NOISE_KEY_SIZE];
	
	/* Remote keys */
	uint8_t remote_e[NOISE_KEY_SIZE];
	uint8_t remote_s[NOISE_KEY_SIZE];
	
	/* Transport keys (after handshake complete) */
	uint8_t tx_key[NOISE_KEY_SIZE];
	uint8_t rx_key[NOISE_KEY_SIZE];
	uint64_t tx_nonce;
	uint64_t rx_nonce;
	
	/* Session metadata */
	uint16_t session_id;
	uint64_t last_activity;
};

/* Duplicate detection cache entry */
struct message_cache_entry {
	uint32_t hash;
	uint64_t timestamp;
	bool valid;
};

#define MESSAGE_CACHE_SIZE 128

/* Function prototypes */
int bitchat_init_identity(struct bitchat_identity *id, const char *nickname);
int bitchat_create_packet(struct bitchat_packet *pkt, uint8_t type, 
                          uint8_t ttl, const uint8_t *payload, uint16_t len);
bool bitchat_is_duplicate(uint32_t hash);
void bitchat_cache_message(uint32_t hash);

/* Crypto functions */
int bitchat_generate_keypair(uint8_t *private_key, uint8_t *public_key);
int bitchat_ecdh(const uint8_t *our_private, const uint8_t *their_public, 
                 uint8_t *shared_secret);
int bitchat_sha256(const uint8_t *data, size_t len, uint8_t *hash);

/* Noise protocol functions */
int noise_init_session(struct noise_session *session, bool initiator,
                       const struct bitchat_identity *identity);
void noise_mix_hash(uint8_t *h, const uint8_t *data, size_t len);
void noise_mix_key(uint8_t *ck, uint8_t *k, const uint8_t *ikm, size_t len);
int noise_encrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len,
                  const uint8_t *plaintext, size_t plaintext_len,
                  uint8_t *ciphertext, uint8_t *tag);
int noise_decrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *tag, uint8_t *plaintext);

/* Noise XX handshake message processing */
int noise_handshake_write_message1(struct noise_session *session, uint8_t *out, size_t *out_len);
int noise_handshake_read_message1(struct noise_session *session, const uint8_t *in, size_t in_len);
int noise_handshake_write_message2(struct noise_session *session, 
                                   const struct bitchat_identity *identity,
                                   uint8_t *out, size_t *out_len);
int noise_handshake_read_message2(struct noise_session *session,
                                  const struct bitchat_identity *identity,
                                  const uint8_t *in, size_t in_len);
int noise_handshake_write_message3(struct noise_session *session,
                                   const struct bitchat_identity *identity,
                                   uint8_t *out, size_t *out_len);
int noise_handshake_read_message3(struct noise_session *session,
                                  const uint8_t *in, size_t in_len);

/* Ephemeral-only handshake (32-byte RESP compatibility for BitChat Android) */
int noise_complete_ephemeral_handshake(struct noise_session *session, const uint8_t *remote_ephemeral);

/* Transport encryption (post-handshake) */
int noise_transport_encrypt(struct noise_session *session, const uint8_t *plaintext,
                            size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len);
int noise_transport_decrypt(struct noise_session *session, const uint8_t *ciphertext,
                            size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len);

#endif /* bitchat_PROTOCOL_H */

