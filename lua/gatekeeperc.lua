local ffi = require("ffi")

-- Structs
-- TODO Define the C data structures for other functional blocks.
ffi.cdef[[

struct gatekeeper_if {
	char     **pci_addrs;
	uint8_t  num_ports;
	char     *name;
	uint16_t num_rx_queues;
	uint16_t num_tx_queues;
	uint32_t arp_cache_timeout_sec;
	/* This struct has hidden fields. */
};

struct net_config {
	int back_iface_enabled;
	/* This struct has hidden fields. */
};

enum policy_action {
	GK_FWD_GT,
	GK_FWD_BCAK_NET,
	GK_DROP,
};

struct lua_ip_routes {
	const char *ip_addr;
	uint8_t    prefix_len;
	uint8_t    policy_id;
};

struct lua_gk_policy {
	uint8_t            policy_id;
	enum policy_action action;
	int                grantor_id;
};

struct gk_config {
	unsigned int lcore_start_id;
	unsigned int lcore_end_id;
	unsigned int flow_ht_size;
	unsigned int max_num_ipv4_rules;
	unsigned int num_ipv4_tbl8s;
	unsigned int max_num_ipv6_rules;
	unsigned int num_ipv6_tbl8s;
	/* This struct has hidden fields. */
};

struct ggu_config {
	unsigned int      lcore_id;
	uint16_t          ggu_src_port;
	uint16_t          ggu_dst_port;
	/* This struct has hidden fields. */
};

struct lls_config {
	unsigned int lcore_id;
	int          debug;
	/* This struct has hidden fields. */
};

]]

-- Functions and wrappers
-- TODO Define the C functions for other functional blocks.
ffi.cdef[[

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs,
	const char **ip_addrs, uint8_t num_ip_addrs);
void lua_free_iface(struct gatekeeper_if *iface);

struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
int lua_init_gk_rt(
	struct gk_config *gk_conf, struct net_config *net_conf,
	struct lua_ip_routes *routes, unsigned int num_routes,
	struct lua_gk_policy *policies, unsigned int num_policies,
	const char **grantor_addrs, unsigned int num_grantors);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf);

struct ggu_config *alloc_ggu_conf(void);
int run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf);
int cleanup_ggu(struct ggu_config *ggu_conf);

struct lls_config *get_lls_conf(void);
int run_lls(struct net_config *net_conf, struct lls_config *lls_conf);

]]

return ffi.C
