module(..., package.seeall)

--
-- C functions exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[

enum gk_flow_state {
	GK_REQUEST,
	GK_GRANTED,
	GK_DECLINED
};

enum protocols {
	TCP = 6,
	UDP = 17,
	IPV4 = 0x0800,
	IPV6 = 0x86DD,
};

struct ipv4_hdr {
	uint8_t  version_ihl;
	uint8_t  type_of_service;
	uint16_t total_length;
	uint16_t packet_id;
	uint16_t fragment_offset;
	uint8_t  time_to_live;
	uint8_t  next_proto_id;
	uint16_t hdr_checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((__packed__));

struct ipv6_hdr {
	uint32_t vtc_flow;
	uint16_t payload_len;
	uint8_t  proto; 
	uint8_t  hop_limits;
	uint8_t  src_addr[16];
	uint8_t  dst_addr[16];
} __attribute__((__packed__));

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sent_seq;
	uint32_t recv_ack;
	uint8_t  data_off;
	uint8_t  tcp_flags;
	uint16_t rx_win;
	uint16_t cksum;
	uint16_t tcp_urp;
} __attribute__((__packed__));

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t dgram_len;
	uint16_t dgram_cksum;
} __attribute__((__packed__));

struct lua_ip_routes {
        const char *ip_addr;
        uint8_t    prefix_len;
        uint8_t    policy_id;
};

struct gt_packet_fields {
	uint16_t outer_ip_ver;
	uint16_t inner_ip_ver;
	uint8_t l4_proto;

	union {
		uint32_t v4;
		uint8_t  v6[16];
	} gatekeeper_server_ip;

	void *l3_hdr;
	void *l4_hdr;
};

struct ip_flow {
	uint16_t proto;

	union {
		struct {
			uint32_t src;
			uint32_t dst;
		} v4;

		struct {
			uint8_t src[16];
			uint8_t dst[16];
		} v6;
	} f;
};

struct ggu_policy {
	uint8_t  state;
	struct ip_flow flow;

	struct {
		union {
			struct {
				uint32_t tx_rate_kb_sec;
				uint32_t cap_expire_sec;
				uint32_t next_renewal_ms;
				uint32_t renewal_step_ms;
			} granted;

			struct {
				uint32_t expire_sec;
			} declined;
		} u;
	}__attribute__((packed)) params;
};

struct ipv4_lpm_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  policy_id;
};

struct ipv6_lpm_route {
	uint8_t ip[16];
	uint8_t depth;
	uint8_t policy_id;
};

struct rte_lpm_config {
	uint32_t max_rules;
	uint32_t number_tbl8s;
	int flags;
};

struct rte_lpm6_config {
	uint32_t max_rules;
	uint32_t number_tbl8s;
	int flags;
};

struct rte_lpm {
	/* This struct has hidden fields. */
};

struct rte_lpm6 {
	/* This struct has hidden fields. */
};

]]

-- Functions and wrappers
ffi.cdef[[

int lua_update_ipv4_lpm(struct rte_lpm *lpm,
	struct lua_ip_routes *routes, unsigned int num_routes);
int lua_update_ipv6_lpm(struct rte_lpm6 *lpm,
	struct lua_ip_routes *routes, unsigned int num_routes);

struct rte_lpm *init_ipv4_lpm(const char *tag,
	const struct rte_lpm_config *lpm_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier);
int lpm_add_ipv4_routes(struct rte_lpm *lpm,
	struct ipv4_lpm_route *routes, unsigned int num_routes);
int lpm_lookup_ipv4(struct rte_lpm *lpm, uint32_t ip);

struct rte_lpm6 *init_ipv6_lpm(const char *tag,
	const struct rte_lpm6_config *lpm6_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier);
int lpm_add_ipv6_routes(struct rte_lpm6 *lpm,
	struct ipv6_lpm_route *routes, unsigned int num_routes);
int lpm_lookup_ipv6(struct rte_lpm6 *lpm, uint8_t *ip);

]]

c = ffi.C
