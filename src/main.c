/* ESP32-C6 bitchat IRC Client
 * Protocol: Noise_XX_25519_ChaChaPoly_SHA256
 * Full mesh P2P messaging over BLE with IRC-style interface
 */
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <zephyr/random/random.h>
#include <psa/crypto.h>
#include <stdlib.h>

#include <string.h>

#include "bitchat_protocol.h"

LOG_MODULE_REGISTER(bitchat, LOG_LEVEL_INF);

/* Forward declarations for globals used by prompt functions */
static struct bitchat_identity local_identity;
static char current_channel[32] = "#bluetooth";

/* Crypto function prototypes */
extern int bitchat_init_identity(struct bitchat_identity *id, const char *nickname);
extern int bitchat_sha256(const uint8_t *data, size_t len, uint8_t *hash);

/* Shell function prototypes */
extern const struct shell *shell_backend_uart_get_ptr(void);

/* ========== BitChat Configuration ========== */

#define MAX_MESSAGE_LEN 100
#define COVER_TRAFFIC_INTERVAL_MS 15000  /* Dummy packets for privacy */

/* Generate random alphanumeric nickname */
static void generate_random_nickname(char *nick, size_t len)
{
	const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	for (size_t i = 0; i < len - 1; i++) {
		nick[i] = charset[sys_rand32_get() % (sizeof(charset) - 1)];
	}
	nick[len - 1] = '\0';
}

/* BitChat GATT Service UUID (official testnet UUIDs) */
#define BT_UUID_BITCHAT_SERVICE_VAL BT_UUID_128_ENCODE(0xF47B5E2D, 0x4A9E, 0x4C5A, 0x9B3F, 0x8E1D2C3A4B5C)
#define BT_UUID_BITCHAT_MESSAGE_VAL BT_UUID_128_ENCODE(0xA1B2C3D4, 0xE5F6, 0x4A5B, 0x8C9D, 0x0E1F2A3B4C5D)

static struct bt_uuid_128 bitchat_svc_uuid = BT_UUID_INIT_128(BT_UUID_BITCHAT_SERVICE_VAL);
static struct bt_uuid_128 bitchat_msg_uuid = BT_UUID_INIT_128(BT_UUID_BITCHAT_MESSAGE_VAL);

/* Static byte array for UUID comparison in scan callback */
static const uint8_t bitchat_svc_uuid_bytes[] = { BT_UUID_BITCHAT_SERVICE_VAL };

/* Advertising data (must be at file scope for BT_DATA_BYTES macro) */
static const struct bt_data bitchat_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_BITCHAT_SERVICE_VAL),
};

/* Bot identity and state - NOTE: local_identity and current_channel declared earlier */
static bool privacy_enabled = false;  /* privacy on */
static bool encryption_enabled = true;  /* E2EE on by default */
static bool stealth_mode = true;  /* stealth on (monitor without handshake) */
static bool bt_debug_enabled = false;  /* Verbose BT logging */
static bool debug_enabled = false;  /* Noise XX / BitChat packet analysis */
static bool bt_ready_flag = false;  /* BLE controller ready */
static uint32_t messages_sent = 0;
static uint32_t messages_received = 0;
static struct bt_conn *active_connections[CONFIG_BT_MAX_CONN];
static uint16_t remote_handles[CONFIG_BT_MAX_CONN];  /* Remote characteristic handles */
static bool connection_ready[CONFIG_BT_MAX_CONN];    /* Connection fully set up */
static uint16_t connection_mtu[CONFIG_BT_MAX_CONN];  /* MTU per connection */
static int connection_count = 0;

/* Per-connection GATT parameters to avoid race conditions */
static struct bt_gatt_subscribe_params subscribe_params[CONFIG_BT_MAX_CONN];
static struct bt_gatt_discover_params discover_params[CONFIG_BT_MAX_CONN];
static struct bt_gatt_exchange_params mtu_exchange_params[CONFIG_BT_MAX_CONN];

/* Noise sessions (one per connection) */
static struct noise_session sessions[CONFIG_BT_MAX_CONN];

/* Work queue for deferred handshake sending (avoid calling GATT write from GATT callback) */
struct handshake_work {
	struct k_work work;
	struct bt_conn *conn;
};

static struct handshake_work handshake_works[CONFIG_BT_MAX_CONN];

/* Work queue for debug dissection (offload heavy printing from callback) */
#define DEBUG_BUFFER_SIZE 2048
struct debug_work {
	struct k_work work;
	uint8_t packet_data[DEBUG_BUFFER_SIZE];
	uint16_t packet_len;
};

static struct debug_work debug_work_item;

/* Work queue for TX debug dissection (offload heavy printing from send path) */
struct tx_debug_work {
	struct k_work work;
	uint8_t packet_data[DEBUG_BUFFER_SIZE];
	uint16_t packet_len;
};

static struct tx_debug_work tx_debug_work_item;

/* Peer tracking - stores discovered peers with keys and nicknames */
#define PEER_CACHE_SIZE 16
static struct {
	uint64_t sender_id;
	char nickname[bitchat_NICKNAME_LEN];
	char channel[32];  /* Channel this peer is on */
	bt_addr_le_t addr;
	uint8_t noise_pubkey[32];  /* X25519 ephemeral public key from handshake */
	uint8_t sign_pubkey[32];   /* Ed25519 signing public key */
	bool has_noise_pubkey;
	bool has_sign_pubkey;
	bool connected;  /* Currently connected to this peer */
	uint64_t last_seen;  /* Timestamp of last activity */
	bool valid;
} peer_cache[PEER_CACHE_SIZE];

/* Nickname cache - maps sender_id to nickname */
#define NICKNAME_CACHE_SIZE 32
static struct {
	uint64_t sender_id;
	char nickname[bitchat_NICKNAME_LEN];
	bool valid;
} nickname_cache[NICKNAME_CACHE_SIZE];

/* Message display ring buffer */
#define MESSAGE_HISTORY_SIZE 10
static struct {
	char from[bitchat_NICKNAME_LEN];
	char text[MAX_MESSAGE_LEN];
	uint64_t timestamp;
	bool valid;
} message_history[MESSAGE_HISTORY_SIZE];
static uint8_t message_history_idx = 0;

/* Message queue for pending messages when no peers available */
#define MESSAGE_QUEUE_SIZE 20
static struct {
	char message[MAX_MESSAGE_LEN];
	uint64_t timestamp;
	bool valid;
} message_queue[MESSAGE_QUEUE_SIZE];
static uint8_t message_queue_head = 0;  /* Where to add new messages */
static uint8_t message_queue_tail = 0;  /* Where to read messages */
static uint8_t message_queue_count = 0; /* Number of queued messages */

/* GPS coordinates for geohash generation */
static double gps_latitude = 37.24624;     /* Area 51, Nevada (default example) */
static double gps_longitude = -115.82334;  /* West = negative */

/* Geohash identity cache */
#define GEOHASH_CACHE_SIZE 10
static struct {
	char channel[32];
	uint8_t channel_hash[32];
	uint8_t identity[32];
	char geohash[12];
	uint64_t last_seen;
	bool valid;
} geohash_cache[GEOHASH_CACHE_SIZE];

/* Message duplicate detection cache */
static struct message_cache_entry message_cache[MESSAGE_CACHE_SIZE];

/* ========== Geohash Encoding ========== */

/* Encode GPS coordinates to geohash string using base32 */
static void encode_geohash(double lat, double lon, int precision, char *output)
{
	const char base32[] = "0123456789bcdefghjkmnpqrstuvwxyz";
	double lat_min = -90.0, lat_max = 90.0;
	double lon_min = -180.0, lon_max = 180.0;
	int idx = 0;
	int bit = 0;
	int ch = 0;
	int char_bit = 0;  /* Track bits within current character (0-4) */
	
	while (idx < precision) {
		if (bit % 2 == 0) {
			/* Longitude */
			double mid = (lon_min + lon_max) / 2;
			if (lon >= mid) {
				ch |= (1 << (4 - char_bit));
				lon_min = mid;
			} else {
				lon_max = mid;
			}
		} else {
			/* Latitude */
			double mid = (lat_min + lat_max) / 2;
			if (lat >= mid) {
				ch |= (1 << (4 - char_bit));
				lat_min = mid;
			} else {
				lat_max = mid;
			}
		}
		
		bit++;
		char_bit++;
		
		if (char_bit == 5) {
			/* Complete character - 5 bits per base32 character */
			output[idx++] = base32[ch];
			char_bit = 0;
			ch = 0;
		}
	}
	output[precision] = '\0';
}

/* Derive geohash-based identity for a channel (reserved for future use) */
static void derive_geohash_identity(const char *channel, uint8_t *channel_hash_out, uint8_t *identity_out) __attribute__((unused));
static void derive_geohash_identity(const char *channel, uint8_t *channel_hash_out, uint8_t *identity_out)
{
	char geohash_str[12];
	int precision = 7;  /* 7 chars = ~150m precision */
	
	/* Generate geohash from current GPS coordinates */
	encode_geohash(gps_latitude, gps_longitude, precision, geohash_str);
	
	/* For #mesh or #bluetooth, use "bluetooth" as the hash string */
	const char *hash_str = geohash_str;
	if (strcmp(channel, "#mesh") == 0 || strcmp(channel, "#bluetooth") == 0) {
		hash_str = "bluetooth";
	}
	
	/* Channel hash = first 32 bytes of geohash string (padded with zeros) */
	size_t hash_len = strlen(hash_str);
	memset(channel_hash_out, 0, 32);
	for (size_t i = 0; i < hash_len && i < 32; i++) {
		channel_hash_out[i] = hash_str[i];
	}
	
	/* Identity = SHA256(geohash || channel || private_key) */
	uint8_t combined[256];
	size_t offset = 0;
	
	/* Add geohash */
	size_t geohash_len = strlen(geohash_str);
	memcpy(combined + offset, geohash_str, geohash_len);
	offset += geohash_len;
	
	/* Add channel name */
	size_t channel_len = strlen(channel);
	memcpy(combined + offset, channel, channel_len);
	offset += channel_len;
	
	/* Add private key */
	memcpy(combined + offset, local_identity.noise_private, 32);
	offset += 32;
	
	/* Hash to create identity */
	bitchat_sha256(combined, offset, identity_out);
}

/* Store or update geohash cache entry */
static void store_geohash(const char *channel, const uint8_t *channel_hash, const uint8_t *identity)
{
	int slot = -1;
	int oldest = 0;
	uint64_t oldest_time = UINT64_MAX;
	
	/* Find existing entry or empty slot */
	for (int i = 0; i < GEOHASH_CACHE_SIZE; i++) {
		if (geohash_cache[i].valid && strcmp(geohash_cache[i].channel, channel) == 0) {
			slot = i;
			break;
		}
		if (!geohash_cache[i].valid) {
			slot = i;
			break;
		}
		if (geohash_cache[i].last_seen < oldest_time) {
			oldest_time = geohash_cache[i].last_seen;
			oldest = i;
		}
	}
	
	if (slot == -1) {
		slot = oldest;
	}
	
	/* Store entry */
	strncpy(geohash_cache[slot].channel, channel, sizeof(geohash_cache[slot].channel) - 1);
	geohash_cache[slot].channel[sizeof(geohash_cache[slot].channel) - 1] = '\0';
	
	if (channel_hash) {
		memcpy(geohash_cache[slot].channel_hash, channel_hash, 32);
	}
	if (identity) {
		memcpy(geohash_cache[slot].identity, identity, 32);
	}
	
	/* Store actual geohash string */
	encode_geohash(gps_latitude, gps_longitude, 7, geohash_cache[slot].geohash);
	
	geohash_cache[slot].last_seen = k_uptime_get();
	geohash_cache[slot].valid = true;
}

/* ========== Duplicate Detection ========== */

static uint32_t simple_hash(const uint8_t *data, size_t len)
{
	uint32_t hash = 5381;
	for (size_t i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + data[i];
	}
	return hash;
}

bool bitchat_is_duplicate(uint32_t hash)
{
	uint64_t now = k_uptime_get();
	
	for (int i = 0; i < MESSAGE_CACHE_SIZE; i++) {
		if (message_cache[i].valid) {
			/* Expire old entries (30 seconds) */
			if (now - message_cache[i].timestamp > 30000) {
				message_cache[i].valid = false;
				continue;
			}
			if (message_cache[i].hash == hash) {
				return true;
			}
		}
	}
	return false;
}

void bitchat_cache_message(uint32_t hash)
{
	/* Find empty or oldest slot */
	int oldest = 0;
	uint64_t oldest_time = UINT64_MAX;
	
	for (int i = 0; i < MESSAGE_CACHE_SIZE; i++) {
		if (!message_cache[i].valid) {
			oldest = i;
			break;
		}
		if (message_cache[i].timestamp < oldest_time) {
			oldest_time = message_cache[i].timestamp;
			oldest = i;
		}
	}
	
	message_cache[oldest].hash = hash;
	message_cache[oldest].timestamp = k_uptime_get();
	message_cache[oldest].valid = true;
}

/* ========== Peer Tracking ========== */

static void add_or_update_peer(uint64_t sender_id, const char *nickname, 
                               const char *channel,
                               const bt_addr_le_t *addr, 
                               const uint8_t *noise_pubkey,
                               const uint8_t *sign_pubkey,
                               bool is_connected)
{
	/* Find existing peer or empty slot */
	int slot = -1;
	int oldest = 0;
	uint64_t oldest_time = UINT64_MAX;
	
	for (int i = 0; i < PEER_CACHE_SIZE; i++) {
		if (!peer_cache[i].valid) {
			slot = i;
			break;
		}
		if (peer_cache[i].sender_id == sender_id) {
			slot = i;
			break;
		}
		if (peer_cache[i].valid && peer_cache[i].last_seen < oldest_time) {
			oldest = i;
			oldest_time = peer_cache[i].last_seen;
		}
	}
	
	if (slot == -1) {
		slot = oldest;  /* Evict oldest */
	}
	
	peer_cache[slot].sender_id = sender_id;
	peer_cache[slot].last_seen = k_uptime_get();
	
	if (nickname) {
		memset(peer_cache[slot].nickname, 0, sizeof(peer_cache[slot].nickname));
		strncpy(peer_cache[slot].nickname, nickname, bitchat_NICKNAME_LEN - 1);
	}
	if (channel) {
		strncpy(peer_cache[slot].channel, channel, sizeof(peer_cache[slot].channel) - 1);
		peer_cache[slot].channel[sizeof(peer_cache[slot].channel) - 1] = '\0';
	} else {
		peer_cache[slot].channel[0] = '\0';  /* No channel info */
	}
	if (addr) {
		memcpy(&peer_cache[slot].addr, addr, sizeof(bt_addr_le_t));
	}
	if (noise_pubkey) {
		memcpy(peer_cache[slot].noise_pubkey, noise_pubkey, 32);
		peer_cache[slot].has_noise_pubkey = true;
	}
	if (sign_pubkey) {
		memcpy(peer_cache[slot].sign_pubkey, sign_pubkey, 32);
		peer_cache[slot].has_sign_pubkey = true;
	}
	
	peer_cache[slot].connected = is_connected;
	peer_cache[slot].valid = true;
}


/* ========== bitchat Packet Creation ========== */

/* Forward declaration of padding function */
static uint16_t bitchat_pad_packet(uint8_t *buffer, uint16_t data_len, uint16_t buffer_size);

/* Serialize packet to buffer with official bitchat format and padding */
static uint16_t bitchat_serialize_packet(const struct bitchat_packet *pkt, uint8_t *buffer, uint16_t buffer_size)
{
	uint8_t *ptr = buffer;
	
	/* Official header: 14 bytes */
	*ptr++ = pkt->header.version;
	*ptr++ = pkt->header.type;
	*ptr++ = pkt->header.ttl;
	
	/* Big-endian 64-bit timestamp */
	uint64_t timestamp_be = pkt->header.timestamp;  /* Already in BE from create_packet */
	memcpy(ptr, &timestamp_be, 8);
	ptr += 8;
	
	*ptr++ = pkt->header.flags;
	
	/* Big-endian 16-bit payload length */
	uint16_t payload_len_be = pkt->header.payload_len;  /* Already in BE from create_packet */
	memcpy(ptr, &payload_len_be, 2);
	ptr += 2;
	
	/* Sender ID: 8 bytes */
	memcpy(ptr, &pkt->sender_id, 8);
	ptr += 8;
	
	/* Optional recipient ID (only if HAS_RECIPIENT flag set) */
	if (pkt->header.flags & bitchat_FLAG_HAS_RECIPIENT) {
		memcpy(ptr, &pkt->recipient_id, 8);
		ptr += 8;
	}
	
	/* Payload */
	uint16_t payload_len = sys_be16_to_cpu(pkt->header.payload_len);
	memcpy(ptr, pkt->payload, payload_len);
	ptr += payload_len;
	
	/* Calculate data length before padding */
	uint16_t data_len = ptr - buffer;
	
	/* Add padding to 256/512/1024/2048 bytes */
	uint16_t padded_size = bitchat_pad_packet(buffer, data_len, buffer_size);
	
	return padded_size;
}

/* Calculate actual size of a packet (not the full buffer) */
static inline uint16_t bitchat_packet_size(const struct bitchat_packet *pkt)
{
	uint16_t payload_len = sys_be16_to_cpu(pkt->header.payload_len);
	uint16_t base_size = 14 + 8 + payload_len;  /* header + sender_id + payload */
	if (pkt->header.flags & bitchat_FLAG_HAS_RECIPIENT) {
		base_size += 8;
	}
	return base_size;
}

/* Create packet using official bitchat protocol format */
int bitchat_create_packet(struct bitchat_packet *pkt, uint8_t type, 
                          uint8_t ttl, const uint8_t *payload, uint16_t len)
{
	if (len > bitchat_MAX_PAYLOAD_SIZE) {
		return -EINVAL;
	}
	
	memset(pkt, 0, sizeof(*pkt));
	
	/* Official format: 14-byte header with big-endian timestamp and length */
	pkt->header.version = 1;
	pkt->header.type = type;
	pkt->header.ttl = MIN(ttl, bitchat_MAX_TTL);
	
	/* Big-endian 64-bit timestamp (milliseconds since epoch) */
	uint64_t timestamp_ms = k_uptime_get();
	pkt->header.timestamp = sys_cpu_to_be64(timestamp_ms);
	
	/* Flags: broadcast messages don't set HAS_RECIPIENT */
	pkt->header.flags = 0;
	
	/* Big-endian 16-bit payload length */
	pkt->header.payload_len = sys_cpu_to_be16(len);
	
	/* Set sender ID (8 bytes) */
	pkt->sender_id = sys_rand32_get();
	
	/* Broadcast recipient - for official protocol, when broadcasting,
	 * we don't include recipient_id field at all (controlled by flags) */
	pkt->recipient_id = bitchat_BROADCAST_ID;
	
	/* Copy payload */
	memcpy(pkt->payload, payload, len);
	
	return 0;
}

/* Pad packet to official bitchat sizes (256/512/1024/2048 bytes) */
static uint16_t bitchat_pad_packet(uint8_t *buffer, uint16_t data_len, uint16_t buffer_size)
{
	/* Determine target padded size */
	uint16_t padded_size;
	if (data_len <= 256) {
		padded_size = 256;
	} else if (data_len <= 512) {
		padded_size = 512;
	} else if (data_len <= 1024) {
		padded_size = 1024;
	} else {
		padded_size = 2048;
	}
	
	if (padded_size > buffer_size) {
		return 0;  /* Error: buffer too small */
	}
	
	/* Add PKCS#7-style padding: fill with byte value = padding length */
	uint8_t pad_len = padded_size - data_len;
	memset(buffer + data_len, pad_len, pad_len);
	
	return padded_size;
}

/* Remove padding from received packet */
static uint16_t bitchat_unpad_packet(const uint8_t *buffer, uint16_t buffer_len)
{
	if (buffer_len == 0) {
		return 0;
	}
	
	/* Read last byte to get padding length */
	uint8_t pad_len = buffer[buffer_len - 1];
	
	/* Validate padding */
	if (pad_len == 0 || pad_len > buffer_len) {
		return buffer_len;  /* No padding or invalid */
	}
	
	/* Verify all padding bytes are correct */
	for (uint16_t i = buffer_len - pad_len; i < buffer_len; i++) {
		if (buffer[i] != pad_len) {
			return buffer_len;  /* Invalid padding */
		}
	}
	
	return buffer_len - pad_len;
}

/* ========== Packet Sending ========== */

/* Forward declarations */
static int get_conn_index(struct bt_conn *conn);
static int bitchat_send_packet_fragmented(struct bt_conn *conn, uint16_t handle,
                                          const struct bitchat_packet *pkt, uint16_t pkt_size,
                                          uint16_t mtu);

/* Static buffer for serializing packets */
static uint8_t send_buffer[bitchat_PADDED_SIZE_2048];

/* Send a bitchat packet (with official format and padding) */
static int bitchat_send_packet(struct bt_conn *conn, uint16_t handle,
                                const struct bitchat_packet *pkt)
{
	if (!conn || !pkt || handle == 0) {
		LOG_ERR("Invalid send parameters: conn=%p handle=0x%04x pkt=%p", 
		        conn, handle, pkt);
		return -EINVAL;
	}
	
	int idx = get_conn_index(conn);
	if (idx < 0) {
		LOG_ERR("Connection not found");
		return -EINVAL;
	}
	
	uint16_t mtu = connection_mtu[idx];
	
	/* Serialize packet with padding */
	uint16_t padded_size = bitchat_serialize_packet(pkt, send_buffer, sizeof(send_buffer));
	
	if (padded_size == 0) {
		LOG_ERR("Failed to serialize packet");
		return -EINVAL;
	}
	
	/* Use fragmentation if packet is larger than MTU */
	if (padded_size > mtu - 3) {
		if (debug_enabled || bt_debug_enabled) {
			printk("[Send] Packet size %u exceeds MTU %u, using fragmentation\n", padded_size, mtu);
		}
		int err = bitchat_send_packet_fragmented(conn, handle, pkt, padded_size, mtu);
		if (err) {
			LOG_ERR("Fragmentation failed: %d", err);
			return err;
		}
		return 0;
	}
	
	if (bt_debug_enabled) {
		char addr[BT_ADDR_LE_STR_LEN];
		bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
		printk("[GATT] Writing %u bytes to handle 0x%04x for %s\n", padded_size, handle, addr);
	}
	
	/* Show TX packet dissection if debug enabled (offload to worker thread) */
	if (debug_enabled && padded_size <= DEBUG_BUFFER_SIZE) {
		memcpy(tx_debug_work_item.packet_data, send_buffer, padded_size);
		tx_debug_work_item.packet_len = padded_size;
		k_work_submit(&tx_debug_work_item.work);
	}
	
	/* Verify connection is still valid before sending */
	if (conn) {
		struct bt_conn_info info;
		if (bt_conn_get_info(conn, &info) != 0) {
			printk("[TX] Connection invalid, cannot send\n");
			return -ENOTCONN;
		}
	} else {
		printk("[TX] NULL connection, cannot send\n");
		return -EINVAL;
	}
	
	/* Send using BLE GATT write without response */
	return bt_gatt_write_without_response(conn, handle, send_buffer, padded_size, false);
}

/* ========== Packet Fragmentation (Legacy - for backwards compat) ========== */

/* Fragment buffer for reassembly */
#define MAX_FRAGMENTS 10
static struct {
	uint32_t message_id;
	uint8_t fragments_received;
	uint8_t total_fragments;
	uint16_t total_size;
	uint8_t data[bitchat_PADDED_SIZE_2048];
	bool active;
} fragment_buffer[MAX_FRAGMENTS];

/* Static buffer for sending fragments (avoid stack overflow) */
static struct bitchat_packet fragment_send_buffer;

/* Send a packet with fragmentation if needed */
static int bitchat_send_packet_fragmented(struct bt_conn *conn, uint16_t handle,
                                          const struct bitchat_packet *pkt, uint16_t pkt_size,
                                          uint16_t mtu)
{
	/* If packet fits in one MTU, send directly */
	if (pkt_size <= mtu - 3) {  /* -3 for ATT header */
		return bt_gatt_write_without_response(conn, handle, pkt, pkt_size, false);
	}
	
	if (debug_enabled) {
		printk("[Frag] Packet %u bytes requires fragmentation (MTU %u)\n", pkt_size, mtu);
	}
	
	/* Fragment the packet */
	uint16_t max_fragment_payload = mtu - 3 - sizeof(struct bitchat_header) - 16 - sizeof(struct bitchat_fragment_info);
	if (max_fragment_payload < 20) {
		/* MTU too small for full fragmentation with encryption.
		 * Try sending without fragment overhead if packet fits in MTU */
		if (pkt_size <= mtu - 3) {
			printk("[Send] Packet %u bytes fits in MTU %u, sending directly (no fragmentation)\n", pkt_size, mtu);
			return bt_gatt_write_without_response(conn, handle, pkt, pkt_size, false);
		}
		LOG_ERR("MTU too small for fragmentation and packet too large: MTU=%u, packet=%u", mtu, pkt_size);
		return -EINVAL;
	}
	
	uint8_t fragment_count = (pkt_size + max_fragment_payload - 1) / max_fragment_payload;
	uint32_t message_id = sys_rand32_get();
	
	for (uint8_t frag_idx = 0; frag_idx < fragment_count; frag_idx++) {
		struct bitchat_packet *frag_pkt = &fragment_send_buffer;
		memset(frag_pkt, 0, sizeof(*frag_pkt));
		
		/* Set fragment type (official protocol uses single 0x20 type) */
		frag_pkt->header.type = bitchat_PKT_FRAGMENT;
		
		frag_pkt->header.version = 1;
		frag_pkt->header.ttl = pkt->header.ttl;
		frag_pkt->header.timestamp = pkt->header.timestamp;
		frag_pkt->sender_id = pkt->sender_id;
		frag_pkt->recipient_id = pkt->recipient_id;
		
		/* Fragment metadata */
		struct bitchat_fragment_info frag_info;
		frag_info.total_size = pkt_size;
		frag_info.fragment_count = fragment_count;
		frag_info.fragment_index = frag_idx;
		frag_info.message_id = message_id;
		
		/* Copy fragment metadata to payload */
		memcpy(frag_pkt->payload, &frag_info, sizeof(frag_info));
		
		/* Copy fragment data */
		uint16_t offset = frag_idx * max_fragment_payload;
		uint16_t frag_len = MIN(max_fragment_payload, pkt_size - offset);
		memcpy(frag_pkt->payload + sizeof(frag_info), ((uint8_t *)pkt) + offset, frag_len);
		
		frag_pkt->header.payload_len = sizeof(frag_info) + frag_len;
		
		/* Send fragment */
		int ret = bt_gatt_write_without_response(conn, handle, frag_pkt,
		                                         sizeof(struct bitchat_header) + 16 + frag_pkt->header.payload_len,
		                                         false);
		if (ret) {
			printk("[Frag] Failed to send fragment %u/%u (err %d)\n", frag_idx + 1, fragment_count, ret);
			return ret;
		}
		
		printk("[Frag] Sent fragment %u/%u (%u bytes)\n", frag_idx + 1, fragment_count, frag_pkt->header.payload_len);
		
		/* Small delay between fragments to avoid overwhelming receiver */
		k_msleep(10);
	}
	
	return 0;
}

/* Reassemble fragmented packet */
__attribute__((unused))
static int bitchat_reassemble_fragment(const struct bitchat_packet *frag_pkt,
                                       struct bitchat_packet **complete_pkt)
{
	if (frag_pkt->header.payload_len < sizeof(struct bitchat_fragment_info)) {
		return -EINVAL;
	}
	
	struct bitchat_fragment_info frag_info;
	memcpy(&frag_info, frag_pkt->payload, sizeof(frag_info));
	
	/* Find or create fragment buffer */
	int buf_idx = -1;
	for (int i = 0; i < MAX_FRAGMENTS; i++) {
		if (fragment_buffer[i].active && fragment_buffer[i].message_id == frag_info.message_id) {
			buf_idx = i;
			break;
		}
	}
	
	if (buf_idx == -1) {
		/* Find empty slot */
		for (int i = 0; i < MAX_FRAGMENTS; i++) {
			if (!fragment_buffer[i].active) {
				buf_idx = i;
				fragment_buffer[i].active = true;
				fragment_buffer[i].message_id = frag_info.message_id;
				fragment_buffer[i].total_fragments = frag_info.fragment_count;
				fragment_buffer[i].total_size = frag_info.total_size;
				fragment_buffer[i].fragments_received = 0;
				break;
			}
		}
		
		if (buf_idx == -1) {
			printk("[Frag] No buffer slots available\n");
			return -ENOMEM;
		}
	}
	
	/* Copy fragment data */
	uint16_t max_frag_payload = 500;  /* Approximate */
	uint16_t offset = frag_info.fragment_index * max_frag_payload;
	uint16_t frag_data_len = frag_pkt->header.payload_len - sizeof(struct bitchat_fragment_info);
	
	memcpy(fragment_buffer[buf_idx].data + offset,
	       frag_pkt->payload + sizeof(struct bitchat_fragment_info),
	       frag_data_len);
	
	fragment_buffer[buf_idx].fragments_received++;
	
	printk("[Frag] Received %u/%u fragments\n",
	       fragment_buffer[buf_idx].fragments_received,
	       fragment_buffer[buf_idx].total_fragments);
	
	/* Check if complete */
	if (fragment_buffer[buf_idx].fragments_received == fragment_buffer[buf_idx].total_fragments) {
		*complete_pkt = (struct bitchat_packet *)fragment_buffer[buf_idx].data;
		fragment_buffer[buf_idx].active = false;
		return 1;  /* Complete */
	}
	
	return 0;  /* Not yet complete */
}

/* ========== Session Management ========== */

static int get_conn_index(struct bt_conn *conn)
{
	for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
		if (active_connections[i] == conn) {
			return i;
		}
	}
	return -1;
}

static struct noise_session *get_session(struct bt_conn *conn)
{
	int idx = get_conn_index(conn);
	if (idx < 0) {
		return NULL;
	}
	return &sessions[idx];
}

static int init_session_for_conn(struct bt_conn *conn, bool initiator)
{
	int idx = get_conn_index(conn);
	if (idx < 0) {
		LOG_ERR("Connection not found");
		return -1;
	}
	
	return noise_init_session(&sessions[idx], initiator, &local_identity);
}

static int send_handshake_packet(struct bt_conn *conn, uint8_t type, 
                                 const uint8_t *handshake_data, size_t handshake_len)
{
	struct bitchat_packet pkt;
	int idx = get_conn_index(conn);
	int ret;
	
	if (idx < 0) {
		LOG_ERR("Connection not found");
		return -1;
	}
	
	/* Ensure connection is ready (MTU exchanged, GATT discovered) */
	if (!connection_ready[idx]) {
		LOG_WRN("Connection not ready yet, cannot send handshake");
		return -EAGAIN;
	}
	
	uint16_t handle = remote_handles[idx] ? remote_handles[idx] : 0x000a;
	
	/* Create bitchat packet with handshake data */
	ret = bitchat_create_packet(&pkt, type, bitchat_MAX_TTL, 
	                           handshake_data, handshake_len);
	if (ret != 0) {
		LOG_ERR("Failed to create handshake packet");
		return ret;
	}
	
	/* Send via BLE */
	ret = bitchat_send_packet(conn, handle, &pkt);
	if (ret != 0) {
		LOG_ERR("Failed to send handshake packet: %d", ret);
	}
	return ret;
}

static int send_encrypted_message(struct bt_conn *conn, uint8_t type, const char *text)
{
	struct noise_session *session = get_session(conn);
	int idx = get_conn_index(conn);
	
	if (idx < 0) {
		LOG_ERR("Connection not found");
		return -1;
	}
	
	/* Ensure connection is ready */
	if (!connection_ready[idx]) {
		LOG_WRN("Connection not ready yet");
		return -EAGAIN;
	}
	
	uint16_t handle = remote_handles[idx] ? remote_handles[idx] : 0x000a;
	
	if (!session || session->state != NOISE_TRANSPORT) {
		LOG_INF("Session not in transport mode, sending plaintext");
		/* Fall back to plaintext */
		struct bitchat_packet pkt;
		if (bitchat_create_packet(&pkt, type, bitchat_MAX_TTL,
		                         (const uint8_t *)text, strlen(text)) != 0) {
			return -1;
		}
		return bitchat_send_packet(conn, handle, &pkt);
	}
	
	/* Encrypt with session keys */
	uint8_t ciphertext[MAX_MESSAGE_LEN + 16];  /* +16 for auth tag */
	size_t ciphertext_len;
	
	if (noise_transport_encrypt(session, (const uint8_t *)text, strlen(text),
	                            ciphertext, &ciphertext_len) != 0) {
		LOG_ERR("Encryption failed");
		return -1;
	}
	
	/* Send encrypted packet (type 0x21 = encrypted message) */
	struct bitchat_packet pkt;
	if (bitchat_create_packet(&pkt, type + 0x20, bitchat_MAX_TTL,
	                         ciphertext, ciphertext_len) != 0) {
		return -1;
	}
	
	return bitchat_send_packet(conn, handle, &pkt);
}

/* ========== Nickname Cache ========== */

static const char *get_nickname(uint64_t sender_id)
{
	for (int i = 0; i < NICKNAME_CACHE_SIZE; i++) {
		if (nickname_cache[i].valid && nickname_cache[i].sender_id == sender_id) {
			return nickname_cache[i].nickname;
		}
	}
	return NULL;
}

static void store_nickname(uint64_t sender_id, const char *nickname)
{
	if (!nickname || strlen(nickname) == 0) {
		return;
	}
	
	/* Check if already exists */
	for (int i = 0; i < NICKNAME_CACHE_SIZE; i++) {
		if (nickname_cache[i].valid && nickname_cache[i].sender_id == sender_id) {
			/* Update existing */
			strncpy(nickname_cache[i].nickname, nickname, bitchat_NICKNAME_LEN - 1);
			nickname_cache[i].nickname[bitchat_NICKNAME_LEN - 1] = '\0';
			return;
		}
	}
	
	/* Find empty slot */
	for (int i = 0; i < NICKNAME_CACHE_SIZE; i++) {
		if (!nickname_cache[i].valid) {
			nickname_cache[i].sender_id = sender_id;
			strncpy(nickname_cache[i].nickname, nickname, bitchat_NICKNAME_LEN - 1);
			nickname_cache[i].nickname[bitchat_NICKNAME_LEN - 1] = '\0';
			nickname_cache[i].valid = true;
			return;
		}
	}
	
	/* Cache full - overwrite oldest (index 0) */
	nickname_cache[0].sender_id = sender_id;
	strncpy(nickname_cache[0].nickname, nickname, bitchat_NICKNAME_LEN - 1);
	nickname_cache[0].nickname[bitchat_NICKNAME_LEN - 1] = '\0';
	nickname_cache[0].valid = true;
}

/* ========== Message Display ========== */

static void store_message(const char *from, const char *text)
{
	int idx = message_history_idx;
	
	strncpy(message_history[idx].from, from, bitchat_NICKNAME_LEN - 1);
	message_history[idx].from[bitchat_NICKNAME_LEN - 1] = '\0';
	
	strncpy(message_history[idx].text, text, MAX_MESSAGE_LEN - 1);
	message_history[idx].text[MAX_MESSAGE_LEN - 1] = '\0';
	
	message_history[idx].timestamp = k_uptime_get();
	message_history[idx].valid = true;
	
	message_history_idx = (message_history_idx + 1) % MESSAGE_HISTORY_SIZE;
	messages_received++;
}

static void display_message(const char *from, const char *text)
{
	printk("\n[Message from %s] %s\n", from, text);
	
	store_message(from, text);
}

/* ========== Message Queue Management ========== */

static void queue_message(const char *message)
{
	/* Security: Validate input */
	if (!message || strlen(message) == 0) {
		return;
	}
	
	if (message_queue_count >= MESSAGE_QUEUE_SIZE) {
		printk("[Queue] Full - dropping oldest message\n");
		/* Advance tail to drop oldest */
		message_queue_tail = (message_queue_tail + 1) % MESSAGE_QUEUE_SIZE;
		message_queue_count--;
	}
	
	/* Security: Bounds-checked copy */
	size_t len = strlen(message);
	if (len >= MAX_MESSAGE_LEN) {
		len = MAX_MESSAGE_LEN - 1;
	}
	memcpy(message_queue[message_queue_head].message, message, len);
	message_queue[message_queue_head].message[len] = '\0';
	message_queue[message_queue_head].timestamp = k_uptime_get();
	message_queue[message_queue_head].valid = true;
	
	message_queue_head = (message_queue_head + 1) % MESSAGE_QUEUE_SIZE;
	message_queue_count++;
}

static bool dequeue_message(char *message_out, size_t max_len)
{
	if (message_queue_count == 0) {
		return false;
	}
	
	/* Get message from tail */
	strncpy(message_out, message_queue[message_queue_tail].message, max_len - 1);
	message_out[max_len - 1] = '\0';
	
	message_queue[message_queue_tail].valid = false;
	message_queue_tail = (message_queue_tail + 1) % MESSAGE_QUEUE_SIZE;
	message_queue_count--;
	
	return true;
}

static void clear_message_queue(void)
{
	message_queue_head = 0;
	message_queue_tail = 0;
	message_queue_count = 0;
	memset(message_queue, 0, sizeof(message_queue));
}

static void send_queued_messages(void)
{
	if (message_queue_count == 0 || connection_count == 0) {
		return;
	}
	
	char message[MAX_MESSAGE_LEN];
	int sent_count = 0;
	
	printk("[Queue] Draining %u queued message(s)...\n", message_queue_count);
	
	/* Send all queued messages */
	while (dequeue_message(message, sizeof(message))) {
		size_t msg_len = strlen(message);
		int sent = 0;
		
		for (int i = 0; i < connection_count; i++) {
			/* Safety: Validate connection is still valid */
			if (!active_connections[i]) {
				continue;
			}
			
			/* Double-check connection state before using */
			struct bt_conn_info info;
			if (bt_conn_get_info(active_connections[i], &info) != 0) {
				continue;  /* Connection no longer valid */
			}
			
			if (connection_ready[i]) {
				uint16_t handle = remote_handles[i] ? remote_handles[i] : 0x000a;
				
				if (handle == 0) {
					continue;
				}
				
				/* Check if we have a transport session */
				struct noise_session *session = get_session(active_connections[i]);
				if (session && session->state == NOISE_TRANSPORT) {
					/* Send encrypted */
					if (send_encrypted_message(active_connections[i], bitchat_PKT_MESSAGE, message) == 0) {
						sent++;
					}
				} else {
					/* Send plaintext */
					struct bitchat_packet pkt;
					if (bitchat_create_packet(&pkt, bitchat_PKT_DELIVERY_ACK, bitchat_MAX_TTL,
					                         (const uint8_t *)message, msg_len) == 0) {
						pkt.header.flags |= bitchat_FLAG_HAS_RECIPIENT;
						pkt.recipient_id = 0xFFFFFFFFFFFFFFFFULL;
						
						if (bitchat_send_packet(active_connections[i], handle, &pkt) == 0) {
							sent++;
						}
					}
				}
			}
		}
		
		if (sent > 0) {
			sent_count++;
		}
	}
	
	if (sent_count > 0) {
		printk("[Queue] Sent %d queued message(s)\n", sent_count);
	}
}

/* Parse TLV payload to detect message type */
static bool is_tlv_handshake(const uint8_t *payload, uint16_t len)
{
	if (len < 2) return false;
	
	/* Check for TLV_NICKNAME followed by TLV_NOISE_INIT/RESP/FINISH */
	if (payload[0] == bitchat_TLV_NICKNAME) {
		uint8_t nick_len = payload[1];
		if (len < 2 + nick_len + 2) return false;
		
		uint8_t next_tlv = payload[2 + nick_len];
		return (next_tlv == bitchat_TLV_NOISE_INIT ||
		        next_tlv == bitchat_TLV_NOISE_RESP ||
		        next_tlv == bitchat_TLV_NOISE_FINISH);
	}
	
	return false;
}

/* ========== GATT Message Characteristic ========== */

static ssize_t on_message_received(struct bt_conn *conn,
				    const struct bt_gatt_attr *attr,
				    const void *buf, uint16_t len,
				    uint16_t offset, uint8_t flags)
{
	if (len < 14 + 8) {  /* header + sender_id minimum */
		printk("[bitchat] Invalid packet size: %u bytes\n", len);
		return len;
	}
	
	/* Remove padding */
	uint16_t unpadded_len = bitchat_unpad_packet((const uint8_t *)buf, len);
	const uint8_t *ptr = (const uint8_t *)buf;
	
	/* Parse header (14 bytes) */
	uint8_t type = ptr[1];
	uint8_t ttl = ptr[2];
	uint64_t timestamp_be;
	memcpy(&timestamp_be, ptr + 3, 8);
	uint8_t msg_flags = ptr[11];
	uint16_t payload_len_be;
	memcpy(&payload_len_be, ptr + 12, 2);
	uint16_t payload_len = sys_be16_to_cpu(payload_len_be);
	ptr += 14;
	
	/* Parse sender_id */
	uint64_t sender_id;
	memcpy(&sender_id, ptr, 8);
	ptr += 8;
	
	/* Optional recipient_id */
	if (msg_flags & bitchat_FLAG_HAS_RECIPIENT) {
		ptr += 8;
	}
	
	/* Check for duplicates */
	uint32_t hash = simple_hash((const uint8_t *)buf, unpadded_len);
	if (bitchat_is_duplicate(hash)) {
		return len;
	}
	bitchat_cache_message(hash);
	
	/* Process plaintext messages only */
	if (type == bitchat_PKT_MESSAGE && payload_len > 0 && payload_len < MAX_MESSAGE_LEN) {
		/* Don't display here - notifications handle all incoming messages
		 * This handler is for writes TO our characteristic, not FROM peers */
		/* char msg[MAX_MESSAGE_LEN + 1];
		memcpy(msg, ptr, payload_len);
		msg[payload_len] = '\0';
		
		char from_str[50];
		snprintf(from_str, sizeof(from_str), "#mesh (0x%llx)", (unsigned long long)sender_id);
		display_message(from_str, msg); */
		
		/* Mesh rebroadcast if TTL > 0 */
		if (ttl > 0) {
			/* TODO: Implement rebroadcast with new format */
		}
	} else if (type != bitchat_PKT_MESSAGE) {
		/* Encrypted or handshake - already logged by notify_func */
	}
	
	return len;
}

/* GATT Service Definition */
BT_GATT_SERVICE_DEFINE(bitchat_svc,
	BT_GATT_PRIMARY_SERVICE(&bitchat_svc_uuid),
	BT_GATT_CHARACTERISTIC(&bitchat_msg_uuid.uuid,
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP | BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_WRITE,
			       NULL, on_message_received, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

/* ========== Bluetooth Connection Callbacks ========== */

static int64_t last_connect_attempt = 0;

/* Work queue for deferred connection (avoids race condition) */
static bool want_to_connect = false;
static bt_addr_le_t target_addr;
static void connect_work_handler(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(connect_work, connect_work_handler);

/* Packet dissector - compact format to minimize printk overhead */
static void dissect_packet(const uint8_t *data, uint16_t length)
{
	if (!debug_enabled || length < 14) {
		return;
	}
	
	/* Parse header */
	uint8_t version = data[0];
	(void)version;  /* Reserved for future use */
	uint8_t type = data[1];
	uint8_t ttl = data[2];
	
	uint64_t timestamp_be;
	memcpy(&timestamp_be, data + 3, 8);
	uint64_t timestamp = sys_be64_to_cpu(timestamp_be);
	
	uint8_t flags = data[11];
	
	uint16_t payload_len_be;
	memcpy(&payload_len_be, data + 12, 2);
	uint16_t payload_len = sys_be16_to_cpu(payload_len_be);
	
	/* Security: Validate payload length */
	if (14 + 8 + payload_len > length) {
		payload_len = length > 22 ? length - 22 : 0;
	}
	
	/* Compact output - all important info on 2 lines */
	const char *type_str = "???";
	switch (type) {
	case bitchat_PKT_MESSAGE: type_str = "MSG"; break;
	case bitchat_PKT_DELIVERY_ACK: type_str = "ACK"; break;
	case bitchat_PKT_READ_RECEIPT: type_str = "READ"; break;
	case bitchat_PKT_NOISE_HANDSHAKE: type_str = "HSHK"; break;
	case bitchat_PKT_NOISE_ENCRYPTED: type_str = "ENC"; break;
	case bitchat_PKT_FRAGMENT: type_str = "FRAG"; break;
	}
	
	printk("\n[PKT] len=%u type=%s ttl=%u ts=%llu flags=0x%02x payload=%u\n",
	       length, type_str, ttl, (unsigned long long)timestamp, flags, payload_len);
	
	/* Parse IDs and payload */
	if (length >= 14 + 8) {
		uint64_t sender_id;
		memcpy(&sender_id, data + 14, 8);
		printk("      sender=0x%016llx", (unsigned long long)sender_id);
		
		const uint8_t *payload_ptr = data + 14 + 8;
		
		if (flags & bitchat_FLAG_HAS_RECIPIENT && length >= 14 + 8 + 8) {
			uint64_t recipient_id;
			memcpy(&recipient_id, data + 14 + 8, 8);
			printk(" recip=0x%016llx", (unsigned long long)recipient_id);
			payload_ptr += 8;
		}
		printk("\n");
		
		/* Compact hexdump */
		if (payload_len > 0) {
			for (uint16_t offset = 0; offset < payload_len; offset += 16) {
				printk("      %04x  ", offset);
				
				for (uint16_t i = 0; i < 16; i++) {
					if (offset + i < payload_len) {
						printk("%02x ", payload_ptr[offset + i]);
					} else {
						printk("   ");
					}
					if (i == 7) printk(" ");
				}
				
				printk(" |");
				for (uint16_t i = 0; i < 16 && offset + i < payload_len; i++) {
					uint8_t c = payload_ptr[offset + i];
					printk("%c", (c >= 32 && c <= 126) ? c : '.');
				}
				printk("|\n");
			}
		}
	}
}

/* Parse TLV payload into structured data */
struct tlv_message {
	char nickname[bitchat_NICKNAME_LEN + 1];
	char channel[32];
	const uint8_t *handshake_data;
	uint8_t handshake_len;
	uint8_t handshake_type;
	bool has_nickname;
	bool has_channel;
	bool has_handshake;
};

static void parse_tlv_payload(const uint8_t *payload, uint16_t payload_len, struct tlv_message *msg)
{
	memset(msg, 0, sizeof(*msg));
	const uint8_t *tlv_ptr = payload;
	
	/* Security: Add iteration limit to prevent infinite loops */
	uint16_t iterations = 0;
	const uint16_t MAX_TLV_ITERATIONS = 50;
	
	while ((tlv_ptr - payload) + 2 <= payload_len && iterations < MAX_TLV_ITERATIONS) {
		iterations++;
		
		uint8_t tlv_type = tlv_ptr[0];
		uint8_t tlv_len = tlv_ptr[1];
		
		/* Security: Validate TLV length */
		if (tlv_len == 0 || (tlv_ptr - payload) + 2 + tlv_len > payload_len) {
			break;
		}
		
		if (tlv_type == bitchat_TLV_NICKNAME && tlv_len > 0 && tlv_len < sizeof(msg->nickname)) {
			/* Security: Validate nickname is printable ASCII */
			bool is_valid = true;
			for (uint8_t i = 0; i < tlv_len; i++) {
				uint8_t c = tlv_ptr[2 + i];
				if (c < 32 || c > 126) {
					is_valid = false;
					break;
				}
			}
			if (is_valid) {
				memcpy(msg->nickname, tlv_ptr + 2, tlv_len);
				msg->nickname[tlv_len] = '\0';
				msg->has_nickname = true;
			}
		} else if (tlv_type == bitchat_TLV_CHANNEL && tlv_len < sizeof(msg->channel)) {
			memcpy(msg->channel, tlv_ptr + 2, tlv_len);
			msg->channel[tlv_len] = '\0';
			/* Verify channel is printable ASCII */
			bool is_printable = true;
			for (int i = 0; i < tlv_len; i++) {
				if (msg->channel[i] < 32 || msg->channel[i] > 126) {
					is_printable = false;
					break;
				}
			}
			if (is_printable) {
				msg->has_channel = true;
			} else {
				msg->channel[0] = '\0';
			}
		} else if (tlv_type == bitchat_TLV_NOISE_INIT || 
		           tlv_type == bitchat_TLV_NOISE_RESP || 
		           tlv_type == bitchat_TLV_NOISE_FINISH) {
			msg->handshake_type = tlv_type;
			msg->handshake_len = tlv_len;
			msg->handshake_data = tlv_ptr + 2;
			msg->has_handshake = true;
		}
		
		tlv_ptr += 2 + tlv_len;
	}
}

/* Check if message is a geohash identity broadcast (not a handshake) */
static bool is_geohash_broadcast(const struct tlv_message *msg)
{
	/* Geohash broadcasts are 32-byte INIT/RESP, optionally with channel name
	 * Android app sends these without channel name (assumes #bluetooth default) */
	return (msg->has_handshake && 
	        msg->handshake_len == 32 && 
	        (msg->handshake_type == bitchat_TLV_NOISE_INIT || 
	         msg->handshake_type == bitchat_TLV_NOISE_RESP));
}

/* Handle geohash identity broadcast */
static void handle_geohash_broadcast(const struct tlv_message *msg, uint64_t sender_id)
{
	/* Use provided channel or default to #bluetooth */
	const char *channel = msg->has_channel ? msg->channel : "#bluetooth";
	
	if (msg->handshake_type == bitchat_TLV_NOISE_INIT) {
		/* Channel hash */
		store_geohash(channel, msg->handshake_data, NULL);
		if (debug_enabled) {
			printk("[Geohash] Stored channel hash for %s from %s\n", 
			       channel, msg->nickname);
		}
	} else if (msg->handshake_type == bitchat_TLV_NOISE_RESP) {
		/* Peer's identity for this channel */
		store_geohash(channel, NULL, msg->handshake_data);
		if (debug_enabled) {
			printk("[Geohash] Discovered identity for %s from %s\n", 
			       channel, msg->nickname);
		}
		
		/* Update peer cache with location channel */
		for (int i = 0; i < PEER_CACHE_SIZE; i++) {
			if (peer_cache[i].valid && peer_cache[i].sender_id == sender_id) {
				strncpy(peer_cache[i].channel, channel, 
				        sizeof(peer_cache[i].channel) - 1);
				peer_cache[i].channel[sizeof(peer_cache[i].channel) - 1] = '\0';
				if (debug_enabled) {
					printk("[Peer] Updated location channel %s for %s\n", 
					       channel, msg->nickname);
				}
				break;
			}
		}
	}
	
	if (debug_enabled) {
		printk("[RX] Geohash %s from 0x%llx (%s@%s)\n",
		       msg->handshake_type == bitchat_TLV_NOISE_INIT ? "channel_hash" : "identity",
		       (unsigned long long)sender_id, msg->nickname, channel);
		printk("  Hash: ");
		for (uint8_t i = 0; i < msg->handshake_len && i < 32; i++) {
			printk("%02x", msg->handshake_data[i]);
		}
		printk("\n");
	}
}

/* Notification callback */
static uint8_t notify_func(struct bt_conn *conn,
			   struct bt_gatt_subscribe_params *params,
			   const void *data, uint16_t length)
{
	if (!data) {
		/* Unsubscription notification - Zephyr is telling us subscription was removed */
		if (debug_enabled) {
			printk("[GATT] Unsubscribed (handle was 0x%04x)\n", params->value_handle);
		}
		/* DO NOT modify params - it belongs to Zephyr! */
		return BT_GATT_ITER_STOP;
	}
	
	/* Remove padding from received packet */
	uint16_t unpadded_len = bitchat_unpad_packet((const uint8_t *)data, length);
	
	/* Offload dissection to worker thread if debug enabled (avoid blocking callback) */
	if (debug_enabled && unpadded_len <= DEBUG_BUFFER_SIZE) {
		memcpy(debug_work_item.packet_data, data, unpadded_len);
		debug_work_item.packet_len = unpadded_len;
		k_work_submit(&debug_work_item.work);
	}
	
	/* Parse official bitchat packet format */
	if (unpadded_len >= 14 + 8) {  /* header + sender_id minimum */
		const uint8_t *ptr = (const uint8_t *)data;
		
		/* Parse header (14 bytes) */
		uint8_t type = ptr[1];
		uint8_t flags = ptr[11];
		uint16_t payload_len_be;
		memcpy(&payload_len_be, ptr + 12, 2);
		uint16_t payload_len = sys_be16_to_cpu(payload_len_be);
		ptr += 14;
		
		/* Parse sender_id (8 bytes) */
		uint64_t sender_id;
		memcpy(&sender_id, ptr, 8);
		ptr += 8;
		
		/* Optional recipient_id */
		if (flags & bitchat_FLAG_HAS_RECIPIENT) {
			ptr += 8;  /* Skip recipient_id */
		}
		
		/* === HANDLE MESSAGE PACKETS (0x01) === */
		if (type == bitchat_PKT_MESSAGE && payload_len > 0 && payload_len < MAX_MESSAGE_LEN) {
			
			/* Check if this is TLV-encoded */
			if (is_tlv_handshake(ptr, payload_len)) {
				/* Parse TLV payload using helper function */
				struct tlv_message tlv_msg;
				parse_tlv_payload(ptr, payload_len, &tlv_msg);
				
				/* Store nickname if present */
				if (tlv_msg.has_nickname) {
					store_nickname(sender_id, tlv_msg.nickname);
				}
				
				/* Check if this is a geohash broadcast (NOT a handshake) */
				if (is_geohash_broadcast(&tlv_msg)) {
					/* Handle geohash identity broadcast */
					handle_geohash_broadcast(&tlv_msg, sender_id);
					
					/* Track peer FIRST so they appear in list command */
					add_or_update_peer(sender_id, tlv_msg.nickname,
					                  tlv_msg.has_channel ? tlv_msg.channel : "#bluetooth",
					                  bt_conn_get_dst(conn),
					                  tlv_msg.handshake_data,
					                  NULL,
					                  true);
					
					/* DO NOT process as Noise handshake - just continue */
					return BT_GATT_ITER_CONTINUE;
				}
				
				/* === THIS IS A REAL NOISE HANDSHAKE === */
				
				/* Determine handshake phase name for display */
				const char *hs_name = "UNKNOWN";
				if (tlv_msg.handshake_type == bitchat_TLV_NOISE_INIT) {
					hs_name = "INIT";
				} else if (tlv_msg.handshake_type == bitchat_TLV_NOISE_RESP) {
					hs_name = "RESP";
				} else if (tlv_msg.handshake_type == bitchat_TLV_NOISE_FINISH) {
					hs_name = "FINISH";
				}
				
			/* Always show basic handshake info (matching working commit behavior) */
			printk("[RX] Noise handshake %s from 0x%llx (%s@%s) len=%u\n",
			       hs_name, (unsigned long long)sender_id,
			       tlv_msg.nickname, tlv_msg.has_channel ? tlv_msg.channel : "?",
			       tlv_msg.handshake_len);
			
			/* Show hex dump only in debug mode */
			if (debug_enabled) {
				printk("  Key material (hex): ");
				for (uint16_t i = 0; i < tlv_msg.handshake_len && i < 80; i++) {
					printk("%02x", tlv_msg.handshake_data[i]);
				}
				if (tlv_msg.handshake_len > 80) {
					printk("...");
				}
				printk("\n");
			}
			
			/* Track peer (store ephemeral key from handshake) */
			add_or_update_peer(sender_id, tlv_msg.nickname,
			                  tlv_msg.has_channel ? tlv_msg.channel : NULL,
			                  bt_conn_get_dst(conn),
			                  tlv_msg.handshake_data,  /* ephemeral or encrypted key */
			                  NULL,  /* sign key not extractable from encrypted payload */
			                  true);  /* connected */
			
			if (debug_enabled) {
				printk("  [Peer] Added %s from %s\n", hs_name, tlv_msg.nickname);
			}
			
			/* === PROCESS HANDSHAKE (unless in stealth mode) === */
			
			if (stealth_mode) {
				if (debug_enabled) {
					printk("  [Stealth] Ignoring handshake\n");
				}
				/* Continue listening for more packets */
				return BT_GATT_ITER_CONTINUE;
			}
			
			/* Get or create Noise session */
			struct noise_session *session = get_session(conn);
			int conn_idx = get_conn_index(conn);
				
				/* === HANDLE NOISE INIT === */
				if (tlv_msg.handshake_type == bitchat_TLV_NOISE_INIT && tlv_msg.handshake_len >= 32) {
					
					/* Initialize responder session if needed */
					if (!session) {
						if (init_session_for_conn(conn, false) == 0) {
							session = get_session(conn);
						}
					}
					
					/* Process message 1 (INIT) */
					if (session && noise_handshake_read_message1(session, tlv_msg.handshake_data, 
					                                             tlv_msg.handshake_len) == 0) {
						
						/* Generate message 2 (RESP) */
						uint8_t msg2[NOISE_KEY_SIZE * 2 + 16];
						size_t msg2_len;
						
						if (noise_handshake_write_message2(session, &local_identity, msg2, &msg2_len) == 0) {
							/* Build TLV response: NICKNAME + CHANNEL + NOISE_RESP */
							uint8_t tlv_payload[256];
							uint8_t *tlv_ptr = tlv_payload;
							
							/* TLV: Nickname */
							*tlv_ptr++ = bitchat_TLV_NICKNAME;
							*tlv_ptr++ = strlen(local_identity.nickname);
							memcpy(tlv_ptr, local_identity.nickname, strlen(local_identity.nickname));
							tlv_ptr += strlen(local_identity.nickname);
							
							/* TLV: Channel */
							*tlv_ptr++ = bitchat_TLV_CHANNEL;
							*tlv_ptr++ = strlen(current_channel);
							memcpy(tlv_ptr, current_channel, strlen(current_channel));
							tlv_ptr += strlen(current_channel);
							
							/* TLV: NOISE_RESP */
							*tlv_ptr++ = bitchat_TLV_NOISE_RESP;
							*tlv_ptr++ = msg2_len;
							memcpy(tlv_ptr, msg2, msg2_len);
							tlv_ptr += msg2_len;
							
							uint16_t total_len = tlv_ptr - tlv_payload;
							
							/* Send MESSAGE packet with TLV */
							struct bitchat_packet pkt;
							if (bitchat_create_packet(&pkt, bitchat_PKT_MESSAGE, 
							                           bitchat_MAX_TTL, 
							                           tlv_payload, total_len) == 0) {
								if (conn_idx >= 0) {
									bitchat_send_packet(conn, remote_handles[conn_idx], &pkt);
									printk("[TX] Sent RESP (80 bytes)\n");
								}
							}
						}
					}
				}
				/* === HANDLE NOISE RESP === */
				else if (tlv_msg.handshake_type == bitchat_TLV_NOISE_RESP && tlv_msg.handshake_len >= 32) {
					
					/* Valid 80-byte RESP to our INIT */
					if (session && session->state == NOISE_SENT_E && tlv_msg.handshake_len >= 80) {
						
						/* Process message 2 (RESP) */
						if (noise_handshake_read_message2(session, &local_identity, 
						                                 tlv_msg.handshake_data, tlv_msg.handshake_len) == 0) {
							
							/* Generate message 3 (FINISH) */
							uint8_t msg3[NOISE_KEY_SIZE];
							size_t msg3_len;
							
							if (noise_handshake_write_message3(session, &local_identity, msg3, &msg3_len) == 0) {
								/* Build TLV response: NICKNAME + CHANNEL + NOISE_FINISH */
								uint8_t tlv_payload[256];
								uint8_t *tlv_ptr = tlv_payload;
								
								/* TLV: Nickname */
								*tlv_ptr++ = bitchat_TLV_NICKNAME;
								*tlv_ptr++ = strlen(local_identity.nickname);
								memcpy(tlv_ptr, local_identity.nickname, strlen(local_identity.nickname));
								tlv_ptr += strlen(local_identity.nickname);
								
								/* TLV: Channel */
								*tlv_ptr++ = bitchat_TLV_CHANNEL;
								*tlv_ptr++ = strlen(current_channel);
								memcpy(tlv_ptr, current_channel, strlen(current_channel));
								tlv_ptr += strlen(current_channel);
								
								/* TLV: NOISE_FINISH */
								*tlv_ptr++ = bitchat_TLV_NOISE_FINISH;
								*tlv_ptr++ = msg3_len;
								memcpy(tlv_ptr, msg3, msg3_len);
								tlv_ptr += msg3_len;
								
								uint16_t total_len = tlv_ptr - tlv_payload;
								
								/* Send MESSAGE packet with TLV */
								struct bitchat_packet pkt;
								if (bitchat_create_packet(&pkt, bitchat_PKT_MESSAGE,
								                           bitchat_MAX_TTL,
								                           tlv_payload, total_len) == 0) {
									if (conn_idx >= 0) {
										bitchat_send_packet(conn, remote_handles[conn_idx], &pkt);
										printk("[TX] Sent FINISH - TRANSPORT MODE ACTIVE\n");
									}
								}
							}
						}
					}
				}
				/* 32-byte "RESP" is actually INIT (peer mislabeled or collision occurred) */
				else if (tlv_msg.handshake_len == 32) {
					printk("[Noise] Peer sent 32-byte RESP (actually INIT) - collision detected\n");
					
					/* ALWAYS reinitialize as responder (even if session exists) to handle collision */
					if (init_session_for_conn(conn, false) == 0) {
						session = get_session(conn);
						printk("[Noise] Reinitialized session as responder for collision resolution\n");
					}
					
					/* Process as message 1 (INIT) */
					if (session && noise_handshake_read_message1(session, tlv_msg.handshake_data, 
					                                             tlv_msg.handshake_len) == 0) {
						
						/* Generate message 2 (RESP) */
						uint8_t msg2[NOISE_KEY_SIZE * 2 + 16];
						size_t msg2_len;
						
						if (noise_handshake_write_message2(session, &local_identity, msg2, &msg2_len) == 0) {
							/* Build TLV response */
							uint8_t tlv_payload[256];
							uint8_t *tlv_ptr = tlv_payload;
							
							*tlv_ptr++ = bitchat_TLV_NICKNAME;
							*tlv_ptr++ = strlen(local_identity.nickname);
							memcpy(tlv_ptr, local_identity.nickname, strlen(local_identity.nickname));
							tlv_ptr += strlen(local_identity.nickname);
							
							*tlv_ptr++ = bitchat_TLV_CHANNEL;
							*tlv_ptr++ = strlen(current_channel);
							memcpy(tlv_ptr, current_channel, strlen(current_channel));
							tlv_ptr += strlen(current_channel);
							
							*tlv_ptr++ = bitchat_TLV_NOISE_RESP;
							*tlv_ptr++ = msg2_len;
							memcpy(tlv_ptr, msg2, msg2_len);
							tlv_ptr += msg2_len;
							
							uint16_t total_len = tlv_ptr - tlv_payload;
							
							struct bitchat_packet pkt;
							if (bitchat_create_packet(&pkt, bitchat_PKT_MESSAGE, 
							                           bitchat_MAX_TTL, 
							                           tlv_payload, total_len) == 0) {
								if (conn_idx >= 0) {
									bitchat_send_packet(conn, remote_handles[conn_idx], &pkt);
									printk("[TX] Sent RESP (to mislabeled INIT)\n");
								}
							}
						}
					}
				}
				/* === HANDLE NOISE FINISH === */
				else if (tlv_msg.handshake_type == bitchat_TLV_NOISE_FINISH && tlv_msg.handshake_len >= 32) {
					
					/* Process message 3 (FINISH) */
					if (session && noise_handshake_read_message3(session, tlv_msg.handshake_data, 
					                                             tlv_msg.handshake_len) == 0) {
						printk("[Handshake] TRANSPORT MODE ACTIVE\n");
					}
				}
				
				messages_received++;
				
			} else {
				/* === REGULAR TEXT MESSAGE (no TLV) === */
				
				char msg[MAX_MESSAGE_LEN + 1];
				memcpy(msg, ptr, payload_len);
				msg[payload_len] = '\0';
				
				/* Extract nickname from "nickname message" format */
				char *space = strchr(msg, ' ');
				if (space && (space - msg) < bitchat_NICKNAME_LEN) {
					char nickname[bitchat_NICKNAME_LEN];
					size_t nick_len = space - msg;
					memcpy(nickname, msg, nick_len);
					nickname[nick_len] = '\0';
					store_nickname(sender_id, nickname);
				}
				
				/* Format and display message */
				const char *nick = get_nickname(sender_id);
				char from_str[80];
				if (nick) {
					snprintf(from_str, sizeof(from_str), "#mesh 0x%llx (%s)", 
					         (unsigned long long)sender_id, nick);
				} else {
					snprintf(from_str, sizeof(from_str), "#mesh 0x%llx", 
					         (unsigned long long)sender_id);
				}
				
				printk("[MSG] %s: %s\n", from_str, msg);
				display_message(from_str, msg);
				messages_received++;
			}
		}
		/* === HANDLE ACK/RECEIPT PACKETS === */
		else if ((type == bitchat_PKT_DELIVERY_ACK || type == bitchat_PKT_READ_RECEIPT) && 
		         payload_len > 0 && payload_len < MAX_MESSAGE_LEN) {
			
			char msg[MAX_MESSAGE_LEN + 1];
			memcpy(msg, ptr, payload_len);
			msg[payload_len] = '\0';
			
			const char *nick = get_nickname(sender_id);
			if (nick) {
				printk("[ACK] type=%u from 0x%llx (%s): %s\n", 
				       type, (unsigned long long)sender_id, nick, msg);
			} else {
				printk("[ACK] type=%u from 0x%llx: %s\n", 
				       type, (unsigned long long)sender_id, msg);
			}
		}
		/* === HANDLE LEGACY NOISE HANDSHAKE PACKETS (0x10) === */
		else if (type == bitchat_PKT_NOISE_HANDSHAKE) {
			
			const char *nick = get_nickname(sender_id);
			struct noise_session *session = get_session(conn);

			if (!session) {
				if (debug_enabled) {
					printk("[RX] Noise INIT from 0x%llx (%s) len=%u\n", 
					       (unsigned long long)sender_id, nick ? nick : "?", payload_len);
					
					printk("  Ephemeral key: ");
					for (uint16_t i = 0; i < payload_len && i < 32; i++) {
						printk("%02x", ptr[i]);
					}
					if (payload_len > 32) printk("...");
					printk("\n");
				}
				
				if (stealth_mode) {
					if (debug_enabled) {
						printk("  [Stealth] Ignoring\n");
					}
				} else {
					/* Initialize responder session */
					if (init_session_for_conn(conn, false) == 0) {
						session = get_session(conn);
						if (noise_handshake_read_message1(session, ptr, payload_len) == 0) {
							/* Send RESP */
							uint8_t msg2[NOISE_KEY_SIZE * 2 + 16];
							size_t msg2_len;
							if (noise_handshake_write_message2(session, &local_identity, 
							                                   msg2, &msg2_len) == 0) {
								send_handshake_packet(conn, bitchat_PKT_NOISE_HANDSHAKE,
								                      msg2, msg2_len);
								printk("[TX] Sent RESP\n");
							}
						}
					}
				}
			}
			/* State = SENT_E = RESP */
			else if (session->state == NOISE_SENT_E) {
				if (debug_enabled) {
					printk("[RX] Noise RESP from 0x%llx (%s) len=%u\n", 
					       (unsigned long long)sender_id, nick ? nick : "?", payload_len);
					
					printk("  Key material: ");
					for (uint16_t i = 0; i < payload_len && i < 64; i++) {
						printk("%02x", ptr[i]);
					}
					if (payload_len > 64) printk("...");
					printk("\n");
				}
				
				if (noise_handshake_read_message2(session, &local_identity, ptr, payload_len) == 0) {
					/* Send FINISH */
					uint8_t msg3[NOISE_KEY_SIZE];
					size_t msg3_len;
					if (noise_handshake_write_message3(session, &local_identity, 
					                                   msg3, &msg3_len) == 0) {
						send_handshake_packet(conn, bitchat_PKT_NOISE_HANDSHAKE,
						                      msg3, msg3_len);
						printk("[TX] Sent FINISH - TRANSPORT MODE ACTIVE\n");
					}
				}
			}
			/* State = RECEIVED_EES_S_ES = FINISH */
			else if (session->state == NOISE_RECEIVED_EES_S_ES) {
				if (debug_enabled) {
					printk("[RX] Noise FINISH from 0x%llx (%s) len=%u\n", 
					       (unsigned long long)sender_id, nick ? nick : "?", payload_len);
					
					printk("  Static key: ");
					for (uint16_t i = 0; i < payload_len && i < 64; i++) {
						printk("%02x", ptr[i]);
					}
					if (payload_len > 64) printk("...");
					printk("\n");
				}
				
				if (noise_handshake_read_message3(session, ptr, payload_len) == 0) {
					printk("[Handshake] TRANSPORT MODE ACTIVE\n");
				}
			}
			else {
				printk("[RX] Unexpected handshake in state %d\n", session->state);
			}
		}
		/* === HANDLE ENCRYPTED/UNKNOWN PACKETS === */
		else {
			struct noise_session *session = get_session(conn);
			
			/* Try to decrypt if we have an active transport session */
			if (session && session->state == NOISE_TRANSPORT && type >= 0x20) {
				
				uint8_t plaintext[MAX_MESSAGE_LEN];
				size_t plaintext_len;
				
				if (noise_transport_decrypt(session, ptr, payload_len,
				                           plaintext, &plaintext_len) == 0) {
					
					/* Decryption successful */
					char msg[MAX_MESSAGE_LEN + 1];
					memcpy(msg, plaintext, plaintext_len);
					msg[plaintext_len] = '\0';
					
					/* Extract nickname */
					char *space = strchr(msg, ' ');
					if (space && (space - msg) < bitchat_NICKNAME_LEN) {
						char nickname[bitchat_NICKNAME_LEN];
						size_t nick_len = space - msg;
						memcpy(nickname, msg, nick_len);
						nickname[nick_len] = '\0';
						store_nickname(sender_id, nickname);
					}
					
					const char *nick = get_nickname(sender_id);
					char from_str[80];
					if (nick) {
						snprintf(from_str, sizeof(from_str), "#mesh 0x%llx (%s)", 
						         (unsigned long long)sender_id, nick);
					} else {
						snprintf(from_str, sizeof(from_str), "#mesh 0x%llx", 
						         (unsigned long long)sender_id);
					}
					
					printk("[MSG] [ENCRYPTED] %s: %s\n", from_str, msg);
					display_message(from_str, msg);
					messages_received++;
				} else {
					/* Decryption failed */
					printk("[RX] Encrypted type=%u len=%u from 0x%llx (decrypt failed)\n", 
					       type, payload_len, (unsigned long long)sender_id);
				}
			} else {
				/* Can't decrypt - show hex dump */
				printk("[RX] Encrypted type=%u len=%u from 0x%llx\n", 
				       type, payload_len, (unsigned long long)sender_id);
				printk("  Hex: ");
				for (uint16_t i = 0; i < payload_len && i < 32; i++) {
					printk("%02x", ptr[i]);
				}
				if (payload_len > 32) {
					printk("...");
				}
				printk("\n");
			}
		}
	}
	
	return BT_GATT_ITER_CONTINUE;
}

/* Work handler for debug dissection - runs in system work queue context */
static void debug_dissect_work_handler(struct k_work *work)
{
	struct debug_work *dw = CONTAINER_OF(work, struct debug_work, work);
	
	/* Run dissector in worker thread - safe to take time here */
	dissect_packet(dw->packet_data, dw->packet_len);
}

/* Work handler for TX debug dissection - runs in system work queue context */
static void tx_debug_dissect_work_handler(struct k_work *work)
{
	struct tx_debug_work *dw = CONTAINER_OF(work, struct tx_debug_work, work);
	
	/* Run TX dissector in worker thread - safe to take time here */
	printk("\n[TX Dissector] Packet to send:\n");
	printk("  Total length: %u bytes (padded)\n", dw->packet_len);
	printk("  Raw data (first 128 bytes):\n");
	uint16_t show_len = dw->packet_len > 128 ? 128 : dw->packet_len;
	for (uint16_t i = 0; i < show_len; i += 16) {
		printk("    %04x  ", i);
		for (uint16_t j = 0; j < 16 && i + j < show_len; j++) {
			printk("%02x ", dw->packet_data[i + j]);
		}
		printk(" |");
		for (uint16_t j = 0; j < 16 && i + j < show_len; j++) {
			uint8_t c = dw->packet_data[i + j];
			printk("%c", (c >= 32 && c < 127) ? c : '.');
		}
		printk("|\n");
	}
	if (dw->packet_len > 128) printk("    ... (%u more bytes)\n", dw->packet_len - 128);
	printk("[End TX Dissector]\n\n");
}

/* Work handler to send handshake - runs in system work queue context */
static void send_handshake_work_handler(struct k_work *work)
{
	struct handshake_work *hs_work = CONTAINER_OF(work, struct handshake_work, work);
	struct bt_conn *conn = hs_work->conn;
	
	if (!conn) {
		printk("[Work] ERROR: NULL connection in handshake work\n");
		return;
	}
	
	int conn_idx = get_conn_index(conn);
	if (conn_idx < 0) {
		printk("[Work] ERROR: Connection not found\n");
		bt_conn_unref(conn);
		return;
	}
	
	struct noise_session *session = get_session(conn);
	if (!session) {
		printk("[Work] ERROR: Session not found\n");
		bt_conn_unref(conn);
		return;
	}
	
	uint8_t msg1[NOISE_KEY_SIZE];
	size_t msg1_len;
	
	if (noise_handshake_write_message1(session, msg1, &msg1_len) == 0) {
		/* Build TLV payload: NICKNAME + CHANNEL + NOISE_INIT */
		uint8_t tlv_payload[256];
		uint8_t *tlv_ptr = tlv_payload;
		
		*tlv_ptr++ = bitchat_TLV_NICKNAME;
		*tlv_ptr++ = strlen(local_identity.nickname);
		memcpy(tlv_ptr, local_identity.nickname, strlen(local_identity.nickname));
		tlv_ptr += strlen(local_identity.nickname);
		
		*tlv_ptr++ = bitchat_TLV_CHANNEL;
		*tlv_ptr++ = strlen(current_channel);
		memcpy(tlv_ptr, current_channel, strlen(current_channel));
		tlv_ptr += strlen(current_channel);
		
		*tlv_ptr++ = bitchat_TLV_NOISE_INIT;
		*tlv_ptr++ = msg1_len;
		memcpy(tlv_ptr, msg1, msg1_len);
		tlv_ptr += msg1_len;
		
		uint16_t total_len = tlv_ptr - tlv_payload;
		
		int ret = send_handshake_packet(conn, bitchat_PKT_MESSAGE, tlv_payload, total_len);
		if (ret == 0) {
			printk("[Handshake] Sent TLV INIT to peer\n");
		} else {
			printk("[Handshake] ERROR: Failed to send INIT (ret=%d)\n", ret);
		}
	} else {
		printk("[Work] ERROR: Failed to write handshake message 1\n");
	}
	
	/* Release reference taken when submitting work */
	bt_conn_unref(conn);
}

/* Subscription complete callback - called when CCC descriptor write finishes */
static void subscribed_func(struct bt_conn *conn,
                            uint8_t err,
                            struct bt_gatt_subscribe_params *params)
{
if (err) {
	printk("[GATT] Subscription CCC write failed (err %d)\n", err);
	return;
}

if (debug_enabled) {
	printk("[GATT] Subscription CCC write complete (notifications enabled)\n");
	if (stealth_mode) {
		printk("[GATT] Waiting for incoming handshake from peer...\n");
	}
}

/* Verify connection before proceeding */
if (!conn) {
printk("[GATT] ERROR: NULL connection in subscription callback\n");
return;
}

int conn_idx = get_conn_index(conn);
if (conn_idx < 0) {
printk("[GATT] ERROR: Connection not found in active connections\n");
return;
}

if (!connection_ready[conn_idx]) {
printk("[GATT] WARNING: Connection not marked ready yet\n");
}

if (remote_handles[conn_idx] == 0) {
printk("[GATT] ERROR: Remote handle not set\n");
return;
}

/* Now safe to send handshake - but defer to work queue to avoid calling
 * bt_gatt_write_without_response from within GATT callback context */
if (!stealth_mode) {
	if (debug_enabled) {
		printk("[GATT] Preparing to send handshake INIT to peer...\n");
	}
	if (init_session_for_conn(conn, true) == 0) {
		/* Submit work to send handshake from system work queue */
		bt_conn_ref(conn);  /* Take reference for work handler */
		handshake_works[conn_idx].conn = conn;
		k_work_submit(&handshake_works[conn_idx].work);
		
		/* Try to send any queued messages now that we have a peer */
		send_queued_messages();
	} else {
		printk("[GATT] ERROR: Failed to init session for connection\n");
	}
} else {
	if (debug_enabled) {
		printk("[GATT] Stealth mode - listening only\n");
	}
}
}
/* GATT discovery callback to find bitchat message characteristic */
static uint8_t discover_func(struct bt_conn *conn,
				     const struct bt_gatt_attr *attr,
				     struct bt_gatt_discover_params *params)
{
	if (!attr) {
		/* Discovery complete */
		return BT_GATT_ITER_STOP;
	}
	
	/* Check if this is the bitchat message characteristic */
	struct bt_gatt_chrc *chrc = (struct bt_gatt_chrc *)attr->user_data;
	if (chrc && bt_uuid_cmp(chrc->uuid, &bitchat_msg_uuid.uuid) == 0) {
		/* Found it! Store the value handle */
		for (int i = 0; i < connection_count; i++) {
			if (active_connections[i] == conn) {
				remote_handles[i] = chrc->value_handle;
				if (debug_enabled) {
					printk("[GATT] Discovered bitchat char handle: 0x%04x\n", chrc->value_handle);
				}
				
				/* Subscribe to notifications */
				memset(&subscribe_params[i], 0, sizeof(subscribe_params[i]));
				subscribe_params[i].notify = notify_func;
				subscribe_params[i].subscribe = subscribed_func;  /* Called when CCC write completes */
				subscribe_params[i].value = BT_GATT_CCC_NOTIFY;
				subscribe_params[i].value_handle = chrc->value_handle;
				subscribe_params[i].ccc_handle = chrc->value_handle + 1; /* CCC is typically next handle */
				
				if (bt_debug_enabled) {
					char addr[BT_ADDR_LE_STR_LEN];
					bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
					printk("[GATT] Subscribing to handle 0x%04x (CCC 0x%04x) for %s\n", 
					       chrc->value_handle, chrc->value_handle + 1, addr);
				}
				
				int ret = bt_gatt_subscribe(conn, &subscribe_params[i]);
				if (ret) {
					printk("[GATT] Subscribe failed (err %d)\n", ret);
				}
				/* Note: INIT will be sent by subscribed_func callback after CCC write completes */
				
				break;
			}
		}
	}
	
	return BT_GATT_ITER_CONTINUE;
}

/* Forward declarations */
static void scan_cb(const bt_addr_le_t *addr, int8_t rssi,
                    uint8_t adv_type, struct net_buf_simple *buf);

/* Scan callback - old style direct callback */
static void scan_cb(const bt_addr_le_t *addr, int8_t rssi,
                    uint8_t adv_type, struct net_buf_simple *buf)
{
	
	/* Debug logging */
	if (bt_debug_enabled) {
		char addr_str[BT_ADDR_LE_STR_LEN];
		bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
		printk("[SCAN] %s RSSI=%d type=%u len=%u\n", 
		       addr_str, rssi, adv_type, buf->len);
	}
	
	/* Skip if we're at max connections */
	if (connection_count >= CONFIG_BT_MAX_CONN) {
		return;
	}
	
	/* Only connect to connectable advertisements with reasonable RSSI */
	if (adv_type != BT_GAP_ADV_TYPE_ADV_IND || rssi < -70) {
		return;
	}
	
	/* Check if advertisement contains BitChat service UUID */
	bool is_bitchat = false;
	struct net_buf_simple_state state;
	net_buf_simple_save(buf, &state);
	
	if (bt_debug_enabled) {
		char addr_str[BT_ADDR_LE_STR_LEN];
		bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
		printk("[Scan] %s - Parsing %u bytes of adv data\n", addr_str, buf->len);
	}
	
	while (buf->len > 1) {
		uint8_t len = net_buf_simple_pull_u8(buf);
		if (len == 0 || buf->len < len) {
			break;
		}
		
		uint8_t type = net_buf_simple_pull_u8(buf);
		len--;
		
		if (bt_debug_enabled) {
			char addr_str[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
			printk("[Scan] %s - AD type=0x%02x len=%u\n", addr_str, type, len);
		}
		
		/* Check if this is a 128-bit UUID list */
		if ((type == BT_DATA_UUID128_ALL || type == BT_DATA_UUID128_SOME) && len >= 16) {
			if (bt_debug_enabled) {
				char addr_str[BT_ADDR_LE_STR_LEN];
				bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
				printk("[Scan] %s - Found UUID128 list, comparing...\n", addr_str);
				printk("  Expected: ");
				for (int i = 0; i < 16; i++) {
					printk("%02x", bitchat_svc_uuid_bytes[i]);
				}
				printk("\n  Got:      ");
				for (int i = 0; i < 16; i++) {
					printk("%02x", buf->data[i]);
				}
				printk("\n");
			}
			
			/* Compare with BitChat service UUID */
			if (memcmp(buf->data, bitchat_svc_uuid_bytes, 16) == 0) {
				is_bitchat = true;
				if (bt_debug_enabled) {
					char addr_str[BT_ADDR_LE_STR_LEN];
					bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
					printk("[Scan] UUID match found for %s\n", addr_str);
				}
				break;
			}
		}
		
		/* Skip remaining data in this AD structure */
		if (buf->len >= len) {
			net_buf_simple_pull_mem(buf, len);
		}
	}
	
	net_buf_simple_restore(buf, &state);
	
	if (!is_bitchat) {
		if (bt_debug_enabled && adv_type == BT_GAP_ADV_TYPE_ADV_IND) {
			char addr_str[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
			printk("[Scan] %s - No BitChat UUID found\n", addr_str);
		}
		return;  /* Not a BitChat device */
	}
	
	/* Check if already connected to this address */
	for (int i = 0; i < connection_count; i++) {
		const bt_addr_le_t *dst = bt_conn_get_dst(active_connections[i]);
		if (bt_addr_le_cmp(dst, addr) == 0) {
			if (bt_debug_enabled) {
				char addr_str[BT_ADDR_LE_STR_LEN];
				bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
				printk("[Scan] %s - Already connected\n", addr_str);
			}
			return;  /* Already connected */
		}
	}
	
	/* Prevent connection race: Use address comparison to decide who connects
	 * If both devices are advertising, they'll both try to connect simultaneously.
	 * Solution: Only initiate connection if our address is LOWER than peer's.
	 * The device with higher address waits to be connected to (peripheral role). */
	if (!stealth_mode) {  /* Only apply this logic when advertising */
		bt_addr_le_t local_addr;
		size_t count = 1;
		bt_id_get(&local_addr, &count);
		
		/* Compare addresses: if peer's address > our address, let them connect to us */
		int cmp = memcmp(addr->a.val, local_addr.a.val, 6);
		if (cmp > 0) {
			if (bt_debug_enabled) {
				char peer_str[BT_ADDR_LE_STR_LEN];
				char local_str[BT_ADDR_LE_STR_LEN];
				bt_addr_le_to_str(addr, peer_str, sizeof(peer_str));
				bt_addr_le_to_str(&local_addr, local_str, sizeof(local_str));
				printk("[Scan] %s > %s - Waiting for peer to connect to us (avoid race)\n", 
				       peer_str, local_str);
			}
			return;  /* Let the other device connect to us */
		}
	}
	
	/* Rate limit (5 seconds between attempts) */
	int64_t now = k_uptime_get();
	if ((now - last_connect_attempt) < 5000) {
		if (bt_debug_enabled) {
			char addr_str[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
			printk("[Scan] %s - Rate limited (%lld ms since last)\n", addr_str, now - last_connect_attempt);
		}
		return;
	}
	
	if (!bt_ready_flag) {
		if (bt_debug_enabled) {
			printk("[Scan] BT not ready\n");
		}
		return;
	}
	
	/* Don't initiate new connection if already attempting */
	if (want_to_connect) {
		if (bt_debug_enabled) {
			printk("[Scan] Connection attempt already in progress\n");
		}
		return;
	}
	
	/* Store target and submit work - NEVER call bt_conn_le_create directly! */
	want_to_connect = true;
	bt_addr_le_copy(&target_addr, addr);
	last_connect_attempt = now;
	
	char addr_str[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	if (debug_enabled) {
		printk("[Mesh] BitChat peer found: %s (RSSI %d) - scheduling connect\n", addr_str, rssi);
	}
	
	/* Submit work with 40ms delay - critical for ESP32-C6 controller stability */
	k_work_schedule(&connect_work, K_MSEC(40));
}

/* Scan parameters structure */
static struct bt_le_scan_param scan_param = {
	.type = BT_HCI_LE_SCAN_ACTIVE,
	.options = BT_LE_SCAN_OPT_NONE,  /* No duplicate filtering for faster discovery */
	.interval = BT_GAP_SCAN_FAST_INTERVAL,
	.window = BT_GAP_SCAN_FAST_WINDOW,
};

/* Connection create parameters - MUST match scan params for parallel operation */
static struct bt_conn_le_create_param create_param = {
	.options = BT_CONN_LE_OPT_NONE,
	.interval = BT_GAP_SCAN_FAST_INTERVAL,
	.window = BT_GAP_SCAN_FAST_WINDOW,
	.timeout = 0,
};

/* Work handler for deferred connection - runs outside scan callback context */
static void connect_work_handler(struct k_work *work)
{
	int err;
	struct bt_conn *conn = NULL;
	
	char addr_str[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(&target_addr, addr_str, sizeof(addr_str));
	if (debug_enabled) {
		printk("[Mesh] Connecting to %s...\n", addr_str);
	}
	
	/* ESP32-C6: DO NOT stop scanning - parallel operation handles it */
	/* Try connection creation while scan is still active */
	err = bt_conn_le_create(&target_addr, &create_param, 
	                        BT_LE_CONN_PARAM_DEFAULT, &conn);
	
	if (err == -EBUSY) {
		printk("[Mesh] Controller busy (-EBUSY) - brief pause and retry\n");
		k_msleep(50);  /* Let HCI commands drain */
		
		/* Retry once */
		err = bt_conn_le_create(&target_addr, &create_param,
		                        BT_LE_CONN_PARAM_DEFAULT, &conn);
	}
	
	if (err) {
		printk("[Mesh] Connection failed (err %d", err);
		if (err == -12) {
			printk(" ENOMEM - out of memory/buffers");
		} else if (err == -5) {
			printk(" EIO - controller error");
		} else if (err == -16) {
			printk(" EBUSY - controller busy");
		} else if (err == -22) {
			printk(" EINVAL - invalid parameters");
		}
		printk(")\n");
		want_to_connect = false;
		/* Scanning should still be active - no need to restart */
	} else {
		if (debug_enabled) {
			printk("[Mesh] Connection initiated successfully\n");
		}
		if (conn) {
			bt_conn_unref(conn);
		}
		want_to_connect = false;
		/* Scanning continues automatically with parallel config */
	}
}

static void mtu_exchange_cb(struct bt_conn *conn, uint8_t err,
                             struct bt_gatt_exchange_params *params)
{
	int conn_idx = -1;
	
	/* Find connection index */
	for (int i = 0; i < connection_count; i++) {
		if (active_connections[i] == conn) {
			conn_idx = i;
			break;
		}
	}
	
	if (conn_idx < 0) {
		printk("[MTU] Exchange callback for unknown connection\n");
		return;
	}
	
	if (!err) {
		uint16_t mtu = bt_gatt_get_mtu(conn);
		connection_mtu[conn_idx] = mtu;
		if (debug_enabled || bt_debug_enabled) {
			char addr[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
			printk("[MTU] Exchange successful: MTU=%u for %s\n", mtu, addr);
		}
	} else {
		if (debug_enabled || bt_debug_enabled) {
			char addr[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
			printk("[MTU] Exchange failed (err %u) for %s, using default MTU 23\n", err, addr);
		}
		connection_mtu[conn_idx] = 23;
	}
	
	/* Mark connection as ready */
	connection_ready[conn_idx] = true;
	
	/* Start GATT service discovery */
	memset(&discover_params[conn_idx], 0, sizeof(discover_params[conn_idx]));
	discover_params[conn_idx].func = discover_func;
	discover_params[conn_idx].uuid = &bitchat_msg_uuid.uuid;
	discover_params[conn_idx].type = BT_GATT_DISCOVER_CHARACTERISTIC;
	discover_params[conn_idx].start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
	discover_params[conn_idx].end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
	
	if (bt_debug_enabled) {
		char addr[BT_ADDR_LE_STR_LEN];
		bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
		printk("[GATT] Starting characteristic discovery for %s\n", addr);
	}
	
	int ret = bt_gatt_discover(conn, &discover_params[conn_idx]);
	if (ret && (debug_enabled || bt_debug_enabled)) {
		printk("[GATT] Discovery start failed (err %d), using default handle\n", ret);
		remote_handles[conn_idx] = 0x000a;
	}
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	
	if (err) {
		printk("Connection failed (err %u), resuming scan\n", err);
		/* Resume scanning on connection failure */
		if (connection_count < CONFIG_BT_MAX_CONN) {
			bt_le_scan_start(&scan_param, scan_cb);
		}
		return;
	}
	
	if (debug_enabled) {
		printk("[Mesh] Connected: %s (peers: %d)\n", addr, connection_count + 1);
	}
	
	if (connection_count < CONFIG_BT_MAX_CONN) {
		active_connections[connection_count] = bt_conn_ref(conn);
		remote_handles[connection_count] = 0;
		connection_ready[connection_count] = false;
		connection_mtu[connection_count] = 23;  /* Default BLE MTU */
		connection_count++;
		
		/* ESP32-C6: Do NOT call bt_le_scan_stop() - parallel scan handles it automatically
		 * and calling stop can cause crashes or not work properly */
		if (connection_count == 1 && debug_enabled) {
			printk("[Scan] Connection established (scan continues in background)\n");
		}
		
		/* Initiate MTU exchange */
		memset(&mtu_exchange_params[connection_count - 1], 0, sizeof(mtu_exchange_params[connection_count - 1]));
		mtu_exchange_params[connection_count - 1].func = mtu_exchange_cb;
		
		if (bt_debug_enabled) {
			char addr[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
			printk("[GATT] Requesting MTU exchange with %s\n", addr);
		}
		
		int ret = bt_gatt_exchange_mtu(conn, &mtu_exchange_params[connection_count - 1]);
		if (ret) {
			printk("[MTU] Exchange request failed (err %d), using default MTU 23\n", ret);
			connection_ready[connection_count - 1] = true;
			connection_mtu[connection_count - 1] = 23;
			remote_handles[connection_count - 1] = 0x000a;
			
			/* Start GATT service discovery even if MTU exchange failed */
			memset(&discover_params[connection_count - 1], 0, sizeof(discover_params[connection_count - 1]));
			discover_params[connection_count - 1].func = discover_func;
			discover_params[connection_count - 1].uuid = &bitchat_msg_uuid.uuid;
			discover_params[connection_count - 1].type = BT_GATT_DISCOVER_CHARACTERISTIC;
			discover_params[connection_count - 1].start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
			discover_params[connection_count - 1].end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
			bt_gatt_discover(conn, &discover_params[connection_count - 1]);
		}
	}
	
	/* Resume scanning if we have room for more connections */
	if (connection_count < CONFIG_BT_MAX_CONN) {
		k_msleep(500);
		bt_le_scan_start(&scan_param, scan_cb);
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	if (debug_enabled) {
		printk("[Mesh] Disconnected: %s (reason %u, peers: %d)\n", addr, reason, connection_count - 1);
	}
	
	/* Mark all peers from this connection as disconnected */
	const bt_addr_le_t *peer_addr = bt_conn_get_dst(conn);
	for (int i = 0; i < PEER_CACHE_SIZE; i++) {
		if (peer_cache[i].valid && 
		    memcmp(&peer_cache[i].addr, peer_addr, sizeof(bt_addr_le_t)) == 0) {
			peer_cache[i].connected = false;
			peer_cache[i].last_seen = k_uptime_get();
		}
	}
	
	/* Remove from active connections */
	for (int i = 0; i < connection_count; i++) {
		if (active_connections[i] == conn) {
			bt_conn_unref(active_connections[i]);
			
			/* Shift remaining connections (if any) */
			if (CONFIG_BT_MAX_CONN > 1) {
				for (int j = i; j < connection_count - 1; j++) {
					active_connections[j] = active_connections[j + 1];
					remote_handles[j] = remote_handles[j + 1];
					connection_ready[j] = connection_ready[j + 1];
					connection_mtu[j] = connection_mtu[j + 1];
				}
			}
			
			/* Clear the last slot */
			active_connections[connection_count - 1] = NULL;
			remote_handles[connection_count - 1] = 0;
			connection_ready[connection_count - 1] = false;
			connection_mtu[connection_count - 1] = 23;
			
			connection_count--;
			break;
		}
	}
	
	/* Restart scanning only when we have NO connections */
	 if (connection_count == 0) {
		printk("[Scan] Restarting scan (no connections)\n");
		bt_le_scan_start(&scan_param, scan_cb);
	}
}

static void le_param_updated(struct bt_conn *conn, uint16_t interval,
                             uint16_t latency, uint16_t timeout)
{
	/* Connection parameters updated - nothing to do */
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.le_param_updated = le_param_updated,
};

/* ========== Cover Traffic Thread ========== */

static void cover_traffic_thread(void)
{
	while (1) {
		k_sleep(K_MSEC(COVER_TRAFFIC_INTERVAL_MS + sys_rand32_get() % 10000));
		
		if (!privacy_enabled || connection_count == 0) {
			continue;
		}
		
		uint8_t dummy[MAX_MESSAGE_LEN];
		sys_rand_get(dummy, sizeof(dummy));
		
		struct bitchat_packet pkt;
		if (bitchat_create_packet(&pkt, bitchat_PKT_MESSAGE, 1, dummy, sizeof(dummy)) == 0) {
			for (int i = 0; i < connection_count; i++) {
				if (active_connections[i] && connection_ready[i]) {
					uint16_t handle = remote_handles[i] ? remote_handles[i] : 0x000a;
					bitchat_send_packet(active_connections[i], handle, &pkt);
				}
			}
		}
	}
}

K_THREAD_DEFINE(cover_thread_id, 4096, cover_traffic_thread, NULL, NULL, NULL, 6, 0, 0);

/* ========== Shell Commands ========== */

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n=== bitchat Status ===");
	shell_print(sh, "Nickname: %s", local_identity.nickname);
	shell_print(sh, "Channel: %s", current_channel);
	shell_print(sh, "Privacy traffic: %s", privacy_enabled ? "ON" : "OFF");
	shell_print(sh, "E2EE: %s", encryption_enabled ? "ON" : "OFF");
	shell_print(sh, "Stealth mode: %s %s", stealth_mode ? "ON" : "OFF",
	           stealth_mode ? "(monitoring only, invisible to peers)" : "(full handshake, visible)");
	shell_print(sh, "\n=== Connections ===");
	shell_print(sh, "Active connections: %u", connection_count);
	for (int i = 0; i < connection_count; i++) {
		char addr[BT_ADDR_LE_STR_LEN];
		if (active_connections[i]) {
			bt_addr_le_to_str(bt_conn_get_dst(active_connections[i]), addr, sizeof(addr));
			shell_print(sh, "  [%d] %s %s", i, 
			           addr,
			           connection_ready[i] ? "READY" : "WAIT");
		}
	}
	shell_print(sh, "\n=== Statistics ===");
	shell_print(sh, "Messages sent: %u", messages_sent);
	shell_print(sh, "Messages received: %u", messages_received);
	
	/* Display identity keys - full hex strings */
	shell_print(sh, "\n=== Identity Keys ===");
	shell_print(sh, "Noise public key:");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.noise_public[i+0], local_identity.noise_public[i+1],
		           local_identity.noise_public[i+2], local_identity.noise_public[i+3],
		           local_identity.noise_public[i+4], local_identity.noise_public[i+5],
		           local_identity.noise_public[i+6], local_identity.noise_public[i+7],
		           local_identity.noise_public[i+8], local_identity.noise_public[i+9],
		           local_identity.noise_public[i+10], local_identity.noise_public[i+11],
		           local_identity.noise_public[i+12], local_identity.noise_public[i+13],
		           local_identity.noise_public[i+14], local_identity.noise_public[i+15]);
	}
	shell_print(sh, "Sign public key:");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.sign_public[i+0], local_identity.sign_public[i+1],
		           local_identity.sign_public[i+2], local_identity.sign_public[i+3],
		           local_identity.sign_public[i+4], local_identity.sign_public[i+5],
		           local_identity.sign_public[i+6], local_identity.sign_public[i+7],
		           local_identity.sign_public[i+8], local_identity.sign_public[i+9],
		           local_identity.sign_public[i+10], local_identity.sign_public[i+11],
		           local_identity.sign_public[i+12], local_identity.sign_public[i+13],
		           local_identity.sign_public[i+14], local_identity.sign_public[i+15]);
	}
	
	return 0;
}

static int cmd_list(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n=== Discovered Peers ===");
	
	int count = 0;
	for (int i = 0; i < PEER_CACHE_SIZE; i++) {
		if (!peer_cache[i].valid) {
			continue;
		}
		
		count++;
		char addr[BT_ADDR_LE_STR_LEN];
		bt_addr_le_to_str(&peer_cache[i].addr, addr, sizeof(addr));
		
		shell_print(sh, "\nPeer #%d:", count);
		shell_print(sh, "  Session ID: 0x%016llx", 
		           (unsigned long long)peer_cache[i].sender_id);
		shell_print(sh, "  Nickname:   %s", peer_cache[i].nickname);
		shell_print(sh, "  Channel:    %s", 
		           peer_cache[i].channel[0] ? peer_cache[i].channel : "(unknown)");
		shell_print(sh, "  BT Address: %s", addr);
		shell_print(sh, "  Status:     %s", 
		           peer_cache[i].connected ? "CONNECTED" : "DISCONNECTED");
		
		uint64_t age_ms = k_uptime_get() - peer_cache[i].last_seen;
		if (age_ms < 1000) {
			shell_print(sh, "  Last seen:  %llu ms ago", (unsigned long long)age_ms);
		} else {
			shell_print(sh, "  Last seen:  %llu sec ago", (unsigned long long)(age_ms / 1000));
		}
		
		if (peer_cache[i].has_noise_pubkey) {
			shell_print(sh, "  Noise Key (X25519):");
			for (int j = 0; j < 32; j += 16) {
				shell_print(sh, "    %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
				           peer_cache[i].noise_pubkey[j+0], peer_cache[i].noise_pubkey[j+1],
				           peer_cache[i].noise_pubkey[j+2], peer_cache[i].noise_pubkey[j+3],
				           peer_cache[i].noise_pubkey[j+4], peer_cache[i].noise_pubkey[j+5],
				           peer_cache[i].noise_pubkey[j+6], peer_cache[i].noise_pubkey[j+7],
				           peer_cache[i].noise_pubkey[j+8], peer_cache[i].noise_pubkey[j+9],
				           peer_cache[i].noise_pubkey[j+10], peer_cache[i].noise_pubkey[j+11],
				           peer_cache[i].noise_pubkey[j+12], peer_cache[i].noise_pubkey[j+13],
				           peer_cache[i].noise_pubkey[j+14], peer_cache[i].noise_pubkey[j+15]);
			}
		}
		
		if (peer_cache[i].has_sign_pubkey) {
			shell_print(sh, "  Sign Key (Ed25519):");
			for (int j = 0; j < 32; j += 16) {
				shell_print(sh, "    %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
				           peer_cache[i].sign_pubkey[j+0], peer_cache[i].sign_pubkey[j+1],
				           peer_cache[i].sign_pubkey[j+2], peer_cache[i].sign_pubkey[j+3],
				           peer_cache[i].sign_pubkey[j+4], peer_cache[i].sign_pubkey[j+5],
				           peer_cache[i].sign_pubkey[j+6], peer_cache[i].sign_pubkey[j+7],
				           peer_cache[i].sign_pubkey[j+8], peer_cache[i].sign_pubkey[j+9],
				           peer_cache[i].sign_pubkey[j+10], peer_cache[i].sign_pubkey[j+11],
				           peer_cache[i].sign_pubkey[j+12], peer_cache[i].sign_pubkey[j+13],
				           peer_cache[i].sign_pubkey[j+14], peer_cache[i].sign_pubkey[j+15]);
			}
		}
	}
	
	if (count == 0) {
		shell_print(sh, "No peers discovered yet.");
		shell_print(sh, "Enable 'debug on' to see handshake captures.");
	} else {
		shell_print(sh, "\nTotal: %d peer(s)", count);
	}
	
	return 0;
}

static int cmd_nick(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: nick <new_nickname>");
		shell_print(sh, "Current nickname: %s", local_identity.nickname);
		return -EINVAL;
	}
	
	const char *new_nick = argv[1];
	size_t len = strlen(new_nick);
	
	/* Security: Limit nickname length */
	if (len == 0) {
		shell_error(sh, "[Error] Nickname cannot be empty");
		return -EINVAL;
	}
	if (len >= bitchat_NICKNAME_LEN) {
		shell_error(sh, "[Error] Nickname too long (max %d chars)", bitchat_NICKNAME_LEN - 1);
		return -EINVAL;
	}
	
	/* Security: Sanitize nickname - only allow printable ASCII, no control chars */
	for (size_t i = 0; i < len; i++) {
		uint8_t c = (uint8_t)new_nick[i];
		if (c < 32 || c > 126) {
			shell_error(sh, "[Error] Nickname contains invalid character at position %zu", i);
			shell_print(sh, "Only printable ASCII characters allowed (32-126)");
			return -EINVAL;
		}
	}
	
	strncpy(local_identity.nickname, new_nick, bitchat_NICKNAME_LEN - 1);
	local_identity.nickname[bitchat_NICKNAME_LEN - 1] = '\0';
	
	shell_print(sh, "[Identity] Nickname changed to: %s", local_identity.nickname);
	return 0;
}

static int cmd_keys_generate(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "[Key] Generating new identity keypairs...");
	
	if (bitchat_init_identity(&local_identity, local_identity.nickname) != 0) {
		shell_print(sh, "[Error] Failed to generate new keys");
		return -EIO;
	}
	
	shell_print(sh, "[Key] New keys generated successfully");
	shell_print(sh, "[Key] Noise public: %02x%02x...%02x%02x",
	           local_identity.noise_public[0], local_identity.noise_public[1],
	           local_identity.noise_public[30], local_identity.noise_public[31]);
	return 0;
}

static int cmd_keys_clear(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "[Key] Clearing identity keys...");
	
	memset(local_identity.noise_private, 0, NOISE_KEY_SIZE);
	memset(local_identity.noise_public, 0, NOISE_KEY_SIZE);
	memset(local_identity.sign_private, 0, NOISE_KEY_SIZE);
	memset(local_identity.sign_public, 0, NOISE_KEY_SIZE);
	
	shell_print(sh, "[Key] All keys cleared (identity is now invalid)");
	shell_print(sh, "[Key] Use 'keys generate' to create new keys");
	return 0;
}

static int cmd_keys_show(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n=== Identity Keys (Public) ===");
	shell_print(sh, "Nickname: %s", local_identity.nickname);
	
	shell_print(sh, "\nNoise public key (32 bytes):");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.noise_public[i+0], local_identity.noise_public[i+1],
		           local_identity.noise_public[i+2], local_identity.noise_public[i+3],
		           local_identity.noise_public[i+4], local_identity.noise_public[i+5],
		           local_identity.noise_public[i+6], local_identity.noise_public[i+7],
		           local_identity.noise_public[i+8], local_identity.noise_public[i+9],
		           local_identity.noise_public[i+10], local_identity.noise_public[i+11],
		           local_identity.noise_public[i+12], local_identity.noise_public[i+13],
		           local_identity.noise_public[i+14], local_identity.noise_public[i+15]);
	}
	
	shell_print(sh, "\nSign public key (32 bytes):");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.sign_public[i+0], local_identity.sign_public[i+1],
		           local_identity.sign_public[i+2], local_identity.sign_public[i+3],
		           local_identity.sign_public[i+4], local_identity.sign_public[i+5],
		           local_identity.sign_public[i+6], local_identity.sign_public[i+7],
		           local_identity.sign_public[i+8], local_identity.sign_public[i+9],
		           local_identity.sign_public[i+10], local_identity.sign_public[i+11],
		           local_identity.sign_public[i+12], local_identity.sign_public[i+13],
		           local_identity.sign_public[i+14], local_identity.sign_public[i+15]);
	}
	
	shell_print(sh, "");
	return 0;
}

static int cmd_keys_showpriv(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n=== Identity Keys (Public + Private) ===");
	shell_print(sh, "Nickname: %s", local_identity.nickname);
	
	shell_print(sh, "\nNoise public key (32 bytes):");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.noise_public[i+0], local_identity.noise_public[i+1],
		           local_identity.noise_public[i+2], local_identity.noise_public[i+3],
		           local_identity.noise_public[i+4], local_identity.noise_public[i+5],
		           local_identity.noise_public[i+6], local_identity.noise_public[i+7],
		           local_identity.noise_public[i+8], local_identity.noise_public[i+9],
		           local_identity.noise_public[i+10], local_identity.noise_public[i+11],
		           local_identity.noise_public[i+12], local_identity.noise_public[i+13],
		           local_identity.noise_public[i+14], local_identity.noise_public[i+15]);
	}
	
	shell_print(sh, "\nNoise private key (32 bytes):");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.noise_private[i+0], local_identity.noise_private[i+1],
		           local_identity.noise_private[i+2], local_identity.noise_private[i+3],
		           local_identity.noise_private[i+4], local_identity.noise_private[i+5],
		           local_identity.noise_private[i+6], local_identity.noise_private[i+7],
		           local_identity.noise_private[i+8], local_identity.noise_private[i+9],
		           local_identity.noise_private[i+10], local_identity.noise_private[i+11],
		           local_identity.noise_private[i+12], local_identity.noise_private[i+13],
		           local_identity.noise_private[i+14], local_identity.noise_private[i+15]);
	}
	
	shell_print(sh, "\nSign public key (32 bytes):");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.sign_public[i+0], local_identity.sign_public[i+1],
		           local_identity.sign_public[i+2], local_identity.sign_public[i+3],
		           local_identity.sign_public[i+4], local_identity.sign_public[i+5],
		           local_identity.sign_public[i+6], local_identity.sign_public[i+7],
		           local_identity.sign_public[i+8], local_identity.sign_public[i+9],
		           local_identity.sign_public[i+10], local_identity.sign_public[i+11],
		           local_identity.sign_public[i+12], local_identity.sign_public[i+13],
		           local_identity.sign_public[i+14], local_identity.sign_public[i+15]);
	}
	
	shell_print(sh, "\nSign private key (32 bytes):");
	for (int i = 0; i < NOISE_KEY_SIZE; i += 16) {
		shell_print(sh, "  %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		           local_identity.sign_private[i+0], local_identity.sign_private[i+1],
		           local_identity.sign_private[i+2], local_identity.sign_private[i+3],
		           local_identity.sign_private[i+4], local_identity.sign_private[i+5],
		           local_identity.sign_private[i+6], local_identity.sign_private[i+7],
		           local_identity.sign_private[i+8], local_identity.sign_private[i+9],
		           local_identity.sign_private[i+10], local_identity.sign_private[i+11],
		           local_identity.sign_private[i+12], local_identity.sign_private[i+13],
		           local_identity.sign_private[i+14], local_identity.sign_private[i+15]);
	}
	
	shell_print(sh, "");
	return 0;
}

static int cmd_messages(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n═══ Recent Messages ═══\n");
	
	int displayed = 0;
	for (int i = 0; i < MESSAGE_HISTORY_SIZE; i++) {
		int idx = (message_history_idx + i) % MESSAGE_HISTORY_SIZE;
		if (message_history[idx].valid) {
			shell_print(sh, "[%llu] %s:", 
			           message_history[idx].timestamp,
			           message_history[idx].from);
			shell_print(sh, "  %s\n", message_history[idx].text);
			displayed++;
		}
	}
	
	if (displayed == 0) {
		shell_print(sh, "  (no messages yet)\n");
	}
	
	return 0;
}

static int cmd_gps(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		/* Display current GPS coordinates */
		shell_print(sh, "=== GPS Coordinates ===");
		
		/* Convert to integers for display (picolibc doesn't support %f) */
		int lat_int = (int)gps_latitude;
		int lat_frac = (int)((gps_latitude - lat_int) * 1000000);
		if (lat_frac < 0) lat_frac = -lat_frac;
		
		int lon_int = (int)gps_longitude;
		int lon_frac = (int)((gps_longitude - lon_int) * 1000000);
		if (lon_frac < 0) lon_frac = -lon_frac;
		
		shell_print(sh, "  Latitude:  %d.%06d", lat_int, lat_frac);
		shell_print(sh, "  Longitude: %s%d.%06d", gps_longitude < 0 ? "" : "", lon_int, lon_frac);
		shell_print(sh, "");
		shell_print(sh, "Geohash precision levels:");
		
		/* Generate and display different precision levels */
		char geohash[12];
		encode_geohash(gps_latitude, gps_longitude, 2, geohash);
		shell_print(sh, "  #%s (region ~1250km)", geohash);
		
		encode_geohash(gps_latitude, gps_longitude, 4, geohash);
		shell_print(sh, "  #%s (province ~39km)", geohash);
		
		encode_geohash(gps_latitude, gps_longitude, 5, geohash);
		shell_print(sh, "  #%s (city ~4.9km)", geohash);
		
		encode_geohash(gps_latitude, gps_longitude, 6, geohash);
		shell_print(sh, "  #%s (neighborhood ~1.2km)", geohash);
		
		encode_geohash(gps_latitude, gps_longitude, 7, geohash);
		shell_print(sh, "  #%s (block ~150m)", geohash);
		
		shell_print(sh, "");
		shell_print(sh, "Usage: gps <lat,lon> to set coordinates");
		shell_print(sh, "Example: gps 37.24624,-115.82334");
		return 0;
	}
	
	/* Parse new coordinates from \"lat,lon\" format */
	const char *coords = argv[1];
	char *comma = strchr(coords, ',');
	if (!comma) {
		shell_error(sh, "Format: gps <lat,lon> (e.g., gps 30.147,-85.651)");
		return -EINVAL;
	}
	
	/* Split into lat and lon strings */
	char lat_str[32], lon_str[32];
	size_t lat_len = comma - coords;
	if (lat_len >= sizeof(lat_str)) {
		shell_error(sh, "Latitude value too long");
		return -EINVAL;
	}
	memcpy(lat_str, coords, lat_len);
	lat_str[lat_len] = '\0';
	
	strncpy(lon_str, comma + 1, sizeof(lon_str) - 1);
	lon_str[sizeof(lon_str) - 1] = '\0';
	
	/* Parse to doubles */
	double new_lat = atof(lat_str);
	double new_lon = atof(lon_str);
	
	/* Validate ranges */
	if (new_lat < -90.0 || new_lat > 90.0) {
		shell_error(sh, "Latitude must be between -90 and 90");
		return -EINVAL;
	}
	if (new_lon < -180.0 || new_lon > 180.0) {
		shell_error(sh, "Longitude must be between -180 and 180");
		return -EINVAL;
	}
	
	/* Update coordinates */
	gps_latitude = new_lat;
	gps_longitude = new_lon;
	
	shell_print(sh, "GPS coordinates updated");
	
	/* Show new geohash */
	char geohash[12];
	encode_geohash(gps_latitude, gps_longitude, 7, geohash);
	shell_print(sh, "New geohash (7-char): #%s", geohash);
	
	return 0;
}

static int cmd_channel(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Current channel: %s", current_channel);
		
		/* Show geohash info for current channel */
		char geohash[12];
		encode_geohash(gps_latitude, gps_longitude, 7, geohash);
		shell_print(sh, "Geohash (7-char): %s (~150m)", geohash);
		
		/* Show different precision levels */
		char gh_region[3], gh_province[5], gh_city[6], gh_neighborhood[7], gh_block[8];
		encode_geohash(gps_latitude, gps_longitude, 2, gh_region);
		encode_geohash(gps_latitude, gps_longitude, 4, gh_province);
		encode_geohash(gps_latitude, gps_longitude, 5, gh_city);
		encode_geohash(gps_latitude, gps_longitude, 6, gh_neighborhood);
		encode_geohash(gps_latitude, gps_longitude, 7, gh_block);
		shell_print(sh, "  #%s (region ~1250km)", gh_region);
		shell_print(sh, "  #%s (province ~39km)", gh_province);
		shell_print(sh, "  #%s (city ~4.9km)", gh_city);
		shell_print(sh, "  #%s (neighborhood ~1.2km)", gh_neighborhood);
		shell_print(sh, "  #%s (block ~150m)", gh_block);
		return 0;
	}
	
	const char *new_channel = argv[1];
	size_t chan_len = strlen(new_channel);
	
	/* Security: Validate channel format */
	if (chan_len == 0 || new_channel[0] != '#') {
		shell_error(sh, "[Error] Channel must start with #");
		return -EINVAL;
	}
	
	if (chan_len >= sizeof(current_channel)) {
		shell_error(sh, "[Error] Channel name too long (max %zu chars)", sizeof(current_channel) - 1);
		return -EINVAL;
	}
	
	/* Security: Sanitize channel name - only allow alphanumeric + # _ - */
	for (size_t i = 0; i < chan_len; i++) {
		char c = new_channel[i];
		if (!(c == '#' || c == '_' || c == '-' || 
		      (c >= '0' && c <= '9') ||
		      (c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z'))) {
			shell_error(sh, "[Error] Invalid character '%c' in channel name", c);
			shell_print(sh, "Only alphanumeric, #, _, and - allowed");
			return -EINVAL;
		}
	}
	
	strncpy(current_channel, new_channel, sizeof(current_channel) - 1);
	current_channel[sizeof(current_channel) - 1] = '\0';
	
	shell_print(sh, "[Channel] Switched to: %s", current_channel);
	return 0;
}

static int cmd_privmsg(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 3) {
		shell_print(sh, "Usage: privmsg <nickname> <message>");
		return -EINVAL;
	}
	
	const char *target = argv[1];
	const char *message = argv[2];
	size_t msg_len = strlen(message);
	
	if (msg_len > MAX_MESSAGE_LEN) {
		shell_print(sh, "[Warning] Message truncated to %d chars", MAX_MESSAGE_LEN);
		msg_len = MAX_MESSAGE_LEN;
	}
	
	if (connection_count == 0) {
		shell_print(sh, "[Error] No peers connected");
		return -ENOTCONN;
	}
	
	/* Create private message packet (target in payload prefix) */
	char privmsg_payload[MAX_MESSAGE_LEN];
	snprintf(privmsg_payload, sizeof(privmsg_payload), "@%s %s", target, message);
	
	/* Send to all ready peers (using encryption if available) */
	int sent = 0;
	int encrypted = 0;
	
	for (int i = 0; i < connection_count; i++) {
		if (active_connections[i] && connection_ready[i]) {
			int err;
			struct noise_session *session = &sessions[i];
			
			if (encryption_enabled && session->state == NOISE_TRANSPORT) {
				/* Send encrypted */
				err = send_encrypted_message(active_connections[i], 
				                            bitchat_PKT_MESSAGE, privmsg_payload);
				if (err == 0) {
					encrypted++;
				}
			} else {
				/* Send plaintext */
				struct bitchat_packet pkt;
				if (bitchat_create_packet(&pkt, bitchat_PKT_MESSAGE, bitchat_MAX_TTL,
				                         (const uint8_t *)privmsg_payload, 
				                         strlen(privmsg_payload)) != 0) {
					continue;
				}
				uint16_t handle = remote_handles[i] ? remote_handles[i] : 0x000a;
				err = bitchat_send_packet(active_connections[i], handle, &pkt);
			}
			
			if (err == 0) {
				sent++;
			}
		}
	}
	
	if (sent == 0) {
		shell_print(sh, "[Error] Failed to send private message");
		return -ENOTCONN;
	}
	
	messages_sent++;
	if (encrypted > 0) {
		shell_print(sh, "[PrivMsg] Sent to @%s (%d peers, %d encrypted, TTL=%d)", 
		           target, sent, encrypted, bitchat_MAX_TTL);
	} else {
		shell_print(sh, "[PrivMsg] Sent to @%s (%d peers, TTL=%d)", target, sent, bitchat_MAX_TTL);
	}
	shell_print(sh, "  Message: \"%s\"", message);
	
	return 0;
}

static int cmd_send(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: send <message>");
		shell_print(sh, "Example: send \"Hello #mesh!\"");
		return -EINVAL;
	}
	
	/* Security: Validate message length early */
	const char *message = argv[1];
	size_t msg_len = strlen(message);
	
	if (msg_len == 0) {
		shell_error(sh, "[Error] Cannot send empty message");
		return -EINVAL;
	}
	
	if (msg_len > MAX_MESSAGE_LEN) {
		shell_error(sh, "[Error] Message too long (%zu chars, max %d)", msg_len, MAX_MESSAGE_LEN);
		return -EINVAL;
	}
	
	if (connection_count == 0) {
		/* Queue message for later delivery */
		queue_message(message);
		shell_print(sh, "[Queue] Message queued (%u in queue)", message_queue_count);
		return 0;
	}
	
	/* Check if in stealth mode - need handshake to send */
	if (stealth_mode) {
		shell_error(sh, "[Error] Cannot send in stealth mode - not handshaked");
	
		return -EPERM;
	}
	
	/* Send to all ready connected peers */
	int sent = 0;
	int encrypted = 0;
	int plaintext = 0;
	
	for (int i = 0; i < connection_count; i++) {
		if (active_connections[i] && connection_ready[i]) {
			uint16_t handle = remote_handles[i] ? remote_handles[i] : 0x000a;
			
			if (handle == 0) {
				printk("[Send] Skipping peer %d (no handle)\n", i);
				continue;
			}
			
			/* Check if we have a transport session for encryption */
			struct noise_session *session = get_session(active_connections[i]);
			if (session && session->state == NOISE_TRANSPORT) {
				/* Send encrypted message */
				if (send_encrypted_message(active_connections[i], bitchat_PKT_MESSAGE, message) == 0) {
					sent++;
					encrypted++;
				}
			} else {
				/* No session - send as plaintext broadcast (use DELIVERY_ACK type for phone compatibility) */
				struct bitchat_packet pkt;
				if (bitchat_create_packet(&pkt, bitchat_PKT_DELIVERY_ACK, bitchat_MAX_TTL,
				                         (const uint8_t *)message, msg_len) == 0) {
					/* Set recipient to broadcast (all peers) */
					pkt.header.flags |= bitchat_FLAG_HAS_RECIPIENT;
					pkt.recipient_id = 0xFFFFFFFFFFFFFFFFULL;
					
					if (bitchat_send_packet(active_connections[i], handle, &pkt) == 0) {
						sent++;
						plaintext++;
					}
				}
			}
		}
	}
	
	if (sent == 0) {
		shell_print(sh, "[Error] Failed to send (no ready connections)");
		return -ENOTCONN;
	}
	
	messages_sent++;
	
	if (encrypted > 0 && plaintext > 0) {
		shell_print(sh, "[Sent] Message to #%s (%d peers: %d encrypted, %d plaintext, TTL=%d)", 
		           current_channel, sent, encrypted, plaintext, bitchat_MAX_TTL);
	} else if (encrypted > 0) {
		shell_print(sh, "[Sent] Encrypted message to #%s (%d peers, TTL=%d)", 
		           current_channel, sent, bitchat_MAX_TTL);
	} else {
		shell_print(sh, "[Sent] Plaintext broadcast to %s (%d peers, TTL=%d)", 
		           current_channel, sent, bitchat_MAX_TTL);
	}
	shell_print(sh, "  Message: \"%s\"", message);
	
	return 0;
}

static int cmd_privacy(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: privacy <on|off>");
		return -EINVAL;
	}
	
	if (strcmp(argv[1], "on") == 0) {
		privacy_enabled = true;
		shell_print(sh, "Privacy traffic enabled (dummy packets for cover)");
	} else if (strcmp(argv[1], "off") == 0) {
		privacy_enabled = false;
		shell_print(sh, "Privacy traffic disabled");
	} else {
		shell_error(sh, "Invalid argument");
		return -EINVAL;
	}
	
	return 0;
}

static int cmd_stealth(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: stealth <on|off>");
		shell_print(sh, "  ON:  Monitor-only mode (invisible to peers, no handshake) - DEFAULT");
		shell_print(sh, "  OFF: Full peer mode (visible, requires Noise XX handshake)");
		shell_print(sh, "");
		shell_print(sh, "Current status: %s", stealth_mode ? "ON (monitoring only)" : "OFF (visible, handshaking)");
		return 0;
	}
	
	if (strcmp(argv[1], "on") == 0) {
		/* Already in stealth mode? */
		if (stealth_mode) {
			shell_print(sh, "Already in stealth mode");
			return 0;
		}
		
		stealth_mode = true;
		
		/* Stop advertising when entering stealth mode */
		int err = bt_le_adv_stop();
		if (err == 0) {
			shell_print(sh, "[BLE] Advertising stopped (stealth mode)");
		}
		
		/* Clear all noise sessions when entering stealth mode */
		for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
			memset(&sessions[i], 0, sizeof(struct noise_session));
			sessions[i].state = NOISE_INIT;
		}
		
		shell_print(sh, "*** Stealth mode ON - monitoring only, sessions cleared");
		shell_print(sh, "    Advertising disabled, scan-only mode");
		shell_print(sh, "    Cannot send messages in stealth mode");
		
	} else if (strcmp(argv[1], "off") == 0) {
		/* Already out of stealth mode? */
		if (!stealth_mode) {
			shell_print(sh, "Already in non-stealth mode");
			return 0;
		}
		
		stealth_mode = false;
		
		/* Start advertising when leaving stealth mode */
		struct bt_le_adv_param adv_param = {
			.id = BT_ID_DEFAULT,
			.options = BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_USE_IDENTITY,
			.interval_min = BT_GAP_ADV_FAST_INT_MIN_2,
			.interval_max = BT_GAP_ADV_FAST_INT_MAX_2,
		};
		
		int err = bt_le_adv_start(&adv_param, bitchat_ad, ARRAY_SIZE(bitchat_ad), NULL, 0);
		if (err == 0) {
			shell_print(sh, "[BLE] Advertising started (non-stealth mode)");
		} else {
			shell_print(sh, "[BLE] Warning: Advertising failed to start (err %d)", err);
		}
		
		/* Initiate handshakes with all connected peers that are ready */
		int initiated = 0;
		int pending = 0;
		for (int i = 0; i < connection_count; i++) {
			if (active_connections[i]) {
				if (!connection_ready[i]) {
					pending++;
					continue;
				}
				
				if (init_session_for_conn(active_connections[i], true) == 0) {
					struct noise_session *session = get_session(active_connections[i]);
					if (session) {
						uint8_t msg1[NOISE_KEY_SIZE];
						size_t msg1_len;
						
						if (noise_handshake_write_message1(session, msg1, &msg1_len) == 0) {
					/* Build TLV payload: NICKNAME + CHANNEL + NOISE_INIT */
					uint8_t tlv_payload[256];
					uint8_t *tlv_ptr = tlv_payload;
					
					/* Add nickname TLV */
					*tlv_ptr++ = bitchat_TLV_NICKNAME;
					*tlv_ptr++ = strlen(local_identity.nickname);
					memcpy(tlv_ptr, local_identity.nickname, strlen(local_identity.nickname));
					tlv_ptr += strlen(local_identity.nickname);
					
					/* Add channel TLV */
					*tlv_ptr++ = bitchat_TLV_CHANNEL;
					*tlv_ptr++ = strlen(current_channel);
					memcpy(tlv_ptr, current_channel, strlen(current_channel));
					tlv_ptr += strlen(current_channel);
							/* Add INIT TLV */
							*tlv_ptr++ = bitchat_TLV_NOISE_INIT;
							*tlv_ptr++ = msg1_len;
							memcpy(tlv_ptr, msg1, msg1_len);
							tlv_ptr += msg1_len;
							
							uint16_t total_len = tlv_ptr - tlv_payload;
							
							/* Send as MESSAGE type with TLV payload */
							int ret = send_handshake_packet(active_connections[i],
							                      bitchat_PKT_MESSAGE,  /* Use MESSAGE type */
							                      tlv_payload, total_len);
							if (ret == 0) {
								initiated++;
							} else if (ret == -EAGAIN) {
								pending++;
							}
						}
					}
				}
			}
		}
		
		shell_print(sh, "*** Stealth mode OFF - initiated handshakes with %d peer(s)", initiated);
		if (pending > 0) {
			shell_print(sh, "    %d connection(s) not yet ready (MTU/GATT pending)", pending);
		}
	} else {
		shell_error(sh, "Invalid argument");
		return -EINVAL;
	}
	
	return 0;
}

/* BT debugging commands */

static int cmd_debug(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: debug <on|off>");
		shell_print(sh, "Enable/disable protocol debugging");
		shell_print(sh, "Current: %s", debug_enabled ? "ON" : "OFF");
		return 0;
	}
	
	if (strcmp(argv[1], "on") == 0) {
		debug_enabled = true;
		shell_print(sh, "*** Protocol Debug ON");
		shell_print(sh, "    Will show detailed packet analysis for handshakes and messages");
	} else if (strcmp(argv[1], "off") == 0) {
		debug_enabled = false;
		shell_print(sh, "*** Protocol Debug OFF");
	} else {
		shell_error(sh, "Invalid argument");
		return -EINVAL;
	}
	
	return 0;
}

static int cmd_btle_debug(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: btle debug <on|off>");
		shell_print(sh, "Enable/disable verbose BLE GATT and controller logging");
		shell_print(sh, "  Shows: GATT operations, write callbacks, MTU exchanges, subscriptions");
		shell_print(sh, "Current: %s", bt_debug_enabled ? "ON" : "OFF");
		return 0;
	}
	
	if (strcmp(argv[1], "on") == 0) {
		bt_debug_enabled = true;
		shell_print(sh, "*** BT Debug ON");
		shell_print(sh, "    Will show GATT operations, write callbacks, MTU exchanges, and connection state");
	} else if (strcmp(argv[1], "off") == 0) {
		bt_debug_enabled = false;
		shell_print(sh, "*** BT Debug OFF");
	} else {
		shell_error(sh, "Invalid argument");
		return -EINVAL;
	}
	
	return 0;
}

static int cmd_btle_info(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n=== Bluetooth Status ===");
	shell_print(sh, "Active connections: %u / %u", connection_count, CONFIG_BT_MAX_CONN);
	
	for (int i = 0; i < connection_count; i++) {
		if (active_connections[i]) {
			char addr[BT_ADDR_LE_STR_LEN];
			bt_addr_le_to_str(bt_conn_get_dst(active_connections[i]), addr, sizeof(addr));
			
			shell_print(sh, "\nConnection %d:", i);
			shell_print(sh, "  Address: %s", addr);
			shell_print(sh, "  MTU: %u", connection_mtu[i]);
			shell_print(sh, "  Handle: 0x%04x", remote_handles[i]);
			shell_print(sh, "  Ready: %s", connection_ready[i] ? "YES" : "NO");
			
			struct noise_session *sess = get_session(active_connections[i]);
			if (sess) {
				const char *state_str = "UNKNOWN";
				switch (sess->state) {
					case NOISE_INIT: state_str = "INIT"; break;
					case NOISE_SENT_E: state_str = "SENT_E"; break;
					case NOISE_RECEIVED_EES_S_ES: state_str = "RECEIVED_EES_S_ES"; break;
					case NOISE_SENT_S_SE: state_str = "SENT_S_SE"; break;
					case NOISE_TRANSPORT: state_str = "TRANSPORT"; break;
				}
				shell_print(sh, "  Noise State: %s", state_str);
				if (sess->state == NOISE_TRANSPORT) {
					shell_print(sh, "  TX Nonce: %llu", sess->tx_nonce);
					shell_print(sh, "  RX Nonce: %llu", sess->rx_nonce);
				}
			}
		}
	}
	
	shell_print(sh, "\n=== BLE Configuration ===");
	shell_print(sh, "Max connections: %u", CONFIG_BT_MAX_CONN);
	shell_print(sh, "L2CAP TX MTU: %u", CONFIG_BT_L2CAP_TX_MTU);
	shell_print(sh, "ACL TX size: %u", CONFIG_BT_BUF_ACL_TX_SIZE);
	shell_print(sh, "ACL RX size: %u", CONFIG_BT_BUF_ACL_RX_SIZE);
	
	return 0;
}

static int cmd_btle_scan(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: btle scan <on|off>");
		return 0;
	}
	
	if (strcmp(argv[1], "on") == 0 || strcmp(argv[1], "start") == 0) {
		int err = bt_le_scan_start(&scan_param, scan_cb);
		if (err) {
			shell_error(sh, "Scan start failed: %d", err);
		} else {
			shell_print(sh, "*** Scanning started");
		}
	} else if (strcmp(argv[1], "off") == 0 || strcmp(argv[1], "stop") == 0) {
		int err = bt_le_scan_stop();
		if (err) {
			shell_error(sh, "Scan stop failed: %d", err);
		} else {
			shell_print(sh, "*** Scanning stopped");
		}
	}
	
	return 0;
}

/* Message Queue Commands */

static int cmd_msgqueue_status(const struct shell *sh, size_t argc, char **argv)
{
	shell_print(sh, "\n=== Message Queue Status ===");
	shell_print(sh, "Messages in queue: %u / %u", message_queue_count, MESSAGE_QUEUE_SIZE);
	
	if (message_queue_count > 0) {
		shell_print(sh, "\nQueued messages:");
		uint8_t idx = message_queue_tail;
		for (uint8_t i = 0; i < message_queue_count; i++) {
			if (message_queue[idx].valid) {
				uint64_t age_ms = k_uptime_get() - message_queue[idx].timestamp;
				shell_print(sh, "  %u. \"%s\" (%llu sec ago)",
				           i + 1,
				           message_queue[idx].message,
				           (unsigned long long)(age_ms / 1000));
			}
			idx = (idx + 1) % MESSAGE_QUEUE_SIZE;
		}
	} else {
		shell_print(sh, "Queue is empty");
	}
	
	return 0;
}

static int cmd_msgqueue_clear(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t count = message_queue_count;
	clear_message_queue();
	shell_print(sh, "[Queue] Cleared %u message(s)", count);
	return 0;
}

/* ========== Shell Command Registration ========== */

/* BTLE subcommands */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_btle,
	SHELL_CMD(debug, NULL, "<on|off> - BLE controller logging", cmd_btle_debug),
	SHELL_CMD(info, NULL, "Show connection details", cmd_btle_info),
	SHELL_CMD(scan, NULL, "<on|off> - Control scanning", cmd_btle_scan),
	SHELL_SUBCMD_SET_END
);

/* Message Queue subcommands */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_msgqueue,
	SHELL_CMD(status, NULL, "Show queued messages", cmd_msgqueue_status),
	SHELL_CMD(clear, NULL, "Clear message queue", cmd_msgqueue_clear),
	SHELL_SUBCMD_SET_END
);

/* bitchat Commands */
SHELL_CMD_REGISTER(debug, NULL, "<on|off> - Debug bitchat protocol", cmd_debug);
SHELL_CMD_REGISTER(status, NULL, "Show bot status and config", cmd_status);
SHELL_CMD_REGISTER(list, NULL, "List discovered peers with keys", cmd_list);
SHELL_CMD_REGISTER(send, NULL, "<message> - Send to current channel", cmd_send);
SHELL_CMD_REGISTER(messages, NULL, "View message history", cmd_messages);
SHELL_CMD_REGISTER(msgqueue, &sub_msgqueue, "Message queue commands", NULL);
SHELL_CMD_REGISTER(nick, NULL, "<name> - Change nickname", cmd_nick);
SHELL_CMD_REGISTER(gps, NULL, "[lat,lon] - Show/set GPS coordinates", cmd_gps);
SHELL_CMD_REGISTER(channel, NULL, "<name> - Join/switch channel", cmd_channel);
SHELL_CMD_REGISTER(join, NULL, "<name> - Alias for channel", cmd_channel);
SHELL_CMD_REGISTER(privmsg, NULL, "<addr> <msg> - Private message", cmd_privmsg);
SHELL_CMD_REGISTER(stealth, NULL, "<on|off> - Stealth mode (default: on)", cmd_stealth);
SHELL_CMD_REGISTER(privacy, NULL, "<on|off> - Privacy cover traffic", cmd_privacy);
SHELL_CMD_REGISTER(cover, NULL, "<on|off> - Alias for privacy", cmd_privacy);

/* Crypto/Key Commands */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_keys,
	SHELL_CMD(show, NULL, "Show public keys only", cmd_keys_show),
	SHELL_CMD(showpriv, NULL, "Show public + private keys", cmd_keys_showpriv),
	SHELL_CMD(generate, NULL, "Generate new keys", cmd_keys_generate),
	SHELL_CMD(clear, NULL, "Clear all keys", cmd_keys_clear),
	SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(keys, &sub_keys, "Key management commands", NULL);

/* Bluetooth Commands */
SHELL_CMD_REGISTER(btle, &sub_btle, "Bluetooth LE commands", NULL);

/* ========== Initialization ========== */

static void bt_ready(int err)
{
	if (err) {
		printk("[BT] Controller init callback failed (err %d)\n", err);
		return;
	}
	
	printk("[BT] Controller ready callback invoked\n");
	bt_ready_flag = true;
}

static int init_bluetooth(void)
{
	printk("=== Initializing Bluetooth ===\n");
	
	int err = bt_enable(bt_ready);
	if (err) {
		printk("[BT] bt_enable() failed (err %d)\n", err);
		return err;
	}
	
	printk("[BT] bt_enable() returned success\n");
	
	/* ESP32-C6 controller may initialize synchronously - check flag */
	if (bt_ready_flag) {
		printk("[BT] Controller initialized synchronously\n");
	} else {
		printk("[BT] Waiting for controller ready callback...\n");
		/* Wait up to 5 seconds for async callback */
		for (int i = 0; i < 50; i++) {
			if (bt_ready_flag) {
				printk("[BT] Controller ready after %d ms\n", i * 100);
				break;
			}
			k_msleep(100);
		}
		
		if (!bt_ready_flag) {
			printk("[BT] WARNING: Controller ready callback never fired\n");
			printk("[BT] Assuming synchronous init and proceeding anyway\n");
			bt_ready_flag = true;  /* Force flag for ESP32-C6 */
		}
	}
	
	printk("[BT] Controller ready, starting services\n");
	
	/* Give controller extra time to fully initialize */
	k_msleep(200);
	
	/* Start advertising ONLY if NOT in stealth mode */
	if (!stealth_mode) {
		struct bt_le_adv_param adv_param = {
			.id = BT_ID_DEFAULT,
			.options = BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_USE_IDENTITY,
			.interval_min = BT_GAP_ADV_FAST_INT_MIN_2,
			.interval_max = BT_GAP_ADV_FAST_INT_MAX_2,
		};
		
		err = bt_le_adv_start(&adv_param, bitchat_ad, ARRAY_SIZE(bitchat_ad), NULL, 0);
		if (err) {
			printk("Advertising failed to start (err %d)\n", err);
			return err;
		}
		
		printk("[BLE] Advertising started (connectable)\n");
		
		/* Let advertising stabilize before starting scan */
		k_msleep(100);
	} else {
		printk("[BLE] Stealth mode - advertising disabled (scan-only)\n");
	}
	
	/* Start scanning (so we can find others) */
	printk("[Scan] Starting active scan for peers...\n");
	err = bt_le_scan_start(&scan_param, scan_cb);
	if (err) {
		printk("Scanning failed to start (err %d)\n", err);
		return err;
	}
	
	printk("[BLE] Scanning started (mesh discovery)\n");
	
	return 0;
}

/* ========== Main ========== */

int main(void)
{
	psa_status_t psa_status;
	
	printk("\n========================================\n");
	printk("  BitChat-ESP32 - Bluetooth Mesh Chat\n");
	printk("  Seeed Studio XIAO ESP32C6\n");
	printk("========================================\n\n");
	
	/* Initialize PSA Crypto */
	printk("[Init] Initializing PSA Crypto...\n");
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS) {
		printk("[FATAL] PSA Crypto init failed: %d\n", psa_status);
		return -1;
	}
	printk("[Crypto] PSA initialized\n");
	
	/* Initialize connection tracking arrays */
	memset(active_connections, 0, sizeof(active_connections));
	memset(remote_handles, 0, sizeof(remote_handles));
	memset(connection_ready, 0, sizeof(connection_ready));
	memset(connection_mtu, 0, sizeof(connection_mtu));
	memset(subscribe_params, 0, sizeof(subscribe_params));
	memset(discover_params, 0, sizeof(discover_params));
	connection_count = 0;
	
	/* Initialize handshake work queue structures */
	for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
		k_work_init(&handshake_works[i].work, send_handshake_work_handler);
		handshake_works[i].conn = NULL;
	}
	
	/* Initialize debug dissection work */
	k_work_init(&debug_work_item.work, debug_dissect_work_handler);
	k_work_init(&tx_debug_work_item.work, tx_debug_dissect_work_handler);
	
	/* Generate ephemeral keypairs on boot (not persisted) */
	printk("[Init] Generating ephemeral identity keys...\n");
	char random_nick[8];
	generate_random_nickname(random_nick, sizeof(random_nick));
	if (bitchat_init_identity(&local_identity, random_nick) != 0) {
		printk("[FATAL] Failed to generate identity\n");
		return -1;
	}
	printk("[Identity] Ready: %s\n", local_identity.nickname);
	
	/* Initialize Bluetooth */
	printk("[Init] Initializing Bluetooth LE...\n");
	if (init_bluetooth() != 0) {
		printk("[FATAL] Bluetooth initialization failed\n");
		return -1;
	}
	printk("[BLE] Bluetooth ready\n");
	
	printk("\n=== bitchat ===\n");
	printk("Joined: %s as %s\n\n", current_channel, local_identity.nickname);
	printk("Available Commands (type 'help' or press Tab for full list):\n");
	printk("  Core:\n");
	printk("    status               - Show system status and connections\n");
	printk("    list                 - List discovered peers with keys\n");
	printk("    send <msg>           - Send message to current channel\n");
	printk("    messages             - View message history\n");
	printk("    privmsg <id> <msg>   - Send private message\n");
	printk("\n");
	printk("  Identity:\n");
	printk("    nick <name>          - Change nickname\n");
	printk("    keys generate        - Generate new identity keypairs\n");
	printk("    keys show            - Show public keys\n");
	printk("\n");
	printk("  Security:\n");
	printk("    stealth <on|off>     - Toggle stealth mode (monitor/participate)\n");
	printk("    privacy <on|off>     - Toggle cover traffic\n");
	printk("    debug <on|off>       - Noise XX/BitChat packet dissector\n");
	printk("\n");
	printk("  Bluetooth:\n");
	printk("    btle info            - Show connection details\n");
	printk("    btle scan <on|off>   - Control BLE scanning\n");
	printk("    btle debug <on|off>  - Toggle bluetooth debugging\n");
	printk("\n");
	
	/* Shell prompt configured via CONFIG_SHELL_PROMPT_UART in prj.conf */
	
	/* Main loop - minimal idle loop, shell handles all interaction */
	while (1) {
		k_msleep(1000);
	}
	
	return 0;
}

