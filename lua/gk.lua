local gatekeeperc = require("gatekeeperc")
local ffi = require("ffi")

local M = {}

function init_lpm(gk_conf, net_conf, segments, gk_policies, gt_addrs)
	local routes =
		ffi.new("struct lua_ip_routes [" .. #segments .. "]")
	for i, v in ipairs(segments) do
		routes[i - 1].ip_addr = v["ip_addr"]
		routes[i - 1].prefix_len = v["prefix_len"]
		routes[i - 1].policy_id = v["policy_id"]
	end

	local policies =
		ffi.new("struct lua_gk_policy [" .. #gk_policies .. "]")
	for i, v in ipairs(gk_policies) do
		policies[i - 1].policy_id = v["policy_id"]
		policies[i - 1].action = v["action"]
		policies[i - 1].grantor_id = v["grantor_id"]
	end

	local grantors =
		ffi.new("const char *[" .. #gt_addrs .. "]")
	for i, v in ipairs(gt_addrs) do
		grantors[i - 1] = v
	end

	return gatekeeperc.lua_init_gk_rt(
		gk_conf, net_conf, routes, #segments,
		policies, #gk_policies, grantors, #gt_addrs)
end

-- Function that sets up the GK functional block.
function M.setup_block(net_conf, numa_table)

	-- Init the GK configuration structure.
	local gk_conf = gatekeeperc.alloc_gk_conf()
	if gk_conf == nil then return nil end
	
	-- Change these parameters to configure the Gatekeeper.
	gk_conf.flow_ht_size = 1024
	local n_lcores = 2

	local gk_lcores = gatekeeper.alloc_lcores_from_same_numa(numa_table,
		n_lcores + 1)
	local ggu_lcore = table.remove(gk_lcores)
	-- TODO Support any sequence of lcore ids.
	gk_conf.lcore_start_id = gk_lcores[1]
	gk_conf.lcore_end_id = gk_lcores[2]

	gk_conf.max_num_ipv4_rules = 1024
	gk_conf.num_ipv4_tbl8s = 256
	gk_conf.max_num_ipv6_rules = 1024
	gk_conf.num_ipv6_tbl8s = 65536

	local segments = {
		{
			["ip_addr"] = "10.0.0.1",
			["prefix_len"] = 24,
			["policy_id"] = 0,
		},
	}

	local policies = {
		{
			["policy_id"] = 0,
			["action"] = ffi.C.GK_FWD_GT,
			["grantor_id"] = 0,
		},
	}

	local grantors = {
		"187.73.35.240",
		"187.73.35.241",
		"3ffe:2501:200:3::1",
	}

	local ret = init_lpm(gk_conf, net_conf, segments, policies, grantors)
	if ret < 0 then return nil end

	-- Setup the GK functional block.
	ret = gatekeeperc.run_gk(net_conf, gk_conf)
	if ret < 0 then return nil end

	return gk_conf, ggu_lcore
end

return M
