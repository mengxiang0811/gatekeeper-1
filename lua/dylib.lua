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

struct gk_fib_dump_entry {
	char     prefix[INET6_ADDRSTRLEN + 5];
	char     grantor_ip[INET6_ADDRSTRLEN];
	bool     stale;
	char     nexthop_ip[INET6_ADDRSTRLEN];
	uint16_t ether_type;
	char     d_addr[ETHER_ADDR_FMT_SIZE];
	char     s_addr[ETHER_ADDR_FMT_SIZE];
	uint32_t ref_cnt;
	enum gk_fib_action action;
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
		local entry = tbl + i - 1
		res[i] = {}
		res[i]["prefix"] = ffi.string(entry.prefix)
		res[i]["grantor_ip"] = ffi.string(entry.grantor_ip)
		res[i]["stale"] = entry.stale
		res[i]["nexthop_ip"] = ffi.string(entry.nexthop_ip)
		res[i]["ether_type"] = entry.ether_type
		res[i]["d_addr"] = ffi.string(entry.d_addr)
		res[i]["s_addr"] = ffi.string(entry.s_addr)
		res[i]["ref_cnt"] = entry.ref_cnt
		res[i]["action"] = entry.action

		i = i + 1
	end

	return res
end
