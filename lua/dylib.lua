module("dylib", package.seeall)

require "gatekeeper"

--
-- C functions exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[

static const uint8_t ETHER_ADDR_FMT_SIZE = 18;
static const uint8_t INET6_ADDRSTRLEN    = 46;

enum gk_fib_action {
	GK_FWD_GRANTOR,
	GK_FWD_GATEWAY_FRONT_NET,
	GK_FWD_GATEWAY_BACK_NET,
	GK_FWD_NEIGHBOR_FRONT_NET,
	GK_FWD_NEIGHBOR_BACK_NET,
	GK_DROP,
	GK_FIB_MAX,
};

struct gk_fib_ether_entry {
	bool     stale;
	char     nexthop_ip[INET6_ADDRSTRLEN];
	uint16_t ether_type;
	char     d_addr[ETHER_ADDR_FMT_SIZE];
	char     s_addr[ETHER_ADDR_FMT_SIZE];
	uint32_t ref_cnt;
};

struct gk_fib_dump_entry {
	char     prefix[INET6_ADDRSTRLEN + 4];
	char     grantor_ip[INET6_ADDRSTRLEN];
	uint16_t num_ether_entries;
	enum gk_fib_action action;
	struct gk_fib_ether_entry *ether_tbl;
};

]]

-- Functions and wrappers
ffi.cdef[[

int add_fib_entry(const char *prefix, const char *gt_ip, const char *gw_ip,
	enum gk_fib_action action, struct gk_config *gk_conf);
int del_fib_entry(const char *ip_prefix, struct gk_config *gk_conf);

struct gk_fib_dump_entry *list_fib_entries(struct gk_config *gk_conf,
	uint32_t *num_entries);

]]

c = ffi.C

--
-- Listing GK FIB entries functions
--

function lua_list_fib_entries(entry_tbl, num_entries)
	local tbl = ffi.cast("struct gk_fib_dump_entry *", entry_tbl)
	local i = 1
	local res = {}

	while (i <= num_entries) do
		local j = 1
		local entry = tbl + i - 1
		local eth_tbl;
		res[i] = {}
		res[i]["prefix"] = ffi.string(entry.prefix)
		res[i]["grantor_ip"] = ffi.string(entry.grantor_ip)
		res[i]["action"] = entry.action

		eth_tbl = ffi.cast("struct gk_fib_ether_entry *",
			entry.ether_tbl)
		while (j <= entry.num_ether_entries) do
			local eth_entry = eth_tbl + j - 1
			res[i][j] = {}
			res[i][j]["stale"] = eth_entry.stale
			res[i][j]["nexthop_ip"] =
				ffi.string(eth_entry.nexthop_ip)
			res[i][j]["ether_type"] = eth_entry.ether_type
			res[i][j]["d_addr"] = ffi.string(eth_entry.d_addr)
			res[i][j]["s_addr"] = ffi.string(eth_entry.s_addr)
			res[i][j]["ref_cnt"] = eth_entry.ref_cnt
			j = j + 1
		end

		i = i + 1
	end

	return res
end
