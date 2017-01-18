return function (net_conf, numa_table)

	-- Init the GK configuration structure.
	local gk_conf = gatekeeper.c.alloc_gk_conf()
	if gk_conf == nil then
		error("Failed to allocate gk_conf")
	end
	
	-- Change these parameters to configure the Gatekeeper.
	gk_conf.flow_ht_size = 1024
	local n_lcores = 2

	local gk_lcores = gatekeeper.alloc_lcores_from_same_numa(numa_table,
		n_lcores + 1)
	local ggu_lcore = table.remove(gk_lcores)
	gatekeeper.gk_assign_lcores(gk_conf, gk_lcores)

	gk_conf.max_num_ipv4_rules = 1024
	gk_conf.num_ipv4_tbl8s = 256
	gk_conf.max_num_ipv6_rules = 1024
	gk_conf.num_ipv6_tbl8s = 65536

	local fib_entries = {

		-- The FIB entries for gateways' configuration.
		{
			["ip_prefix"] = "128.197.41.100/24",
			["action"] = gatekeeper.c.GK_FWD_GATEWAY,
			["gateway"] = "10.0.0.254",
		},

		{
			["ip_prefix"] = "3ffe:2501:200:3::1/48",
			["action"] = gatekeeper.c.GK_FWD_GATEWAY,
			["gateway"] = "fe80::21e:67ff:fe85:1",
		},

		-- The FIB entries for IP prefixes' configuration.
		{
			["ip_prefix"] = "187.73.30.0/30",
			["action"] = gatekeeper.c.GK_FWD_GRANTOR,
			["grantor"] = "128.197.41.100",
		},

		{
			["ip_prefix"] = "2604:a880:400:d0::14:1/48",
			["action"] = gatekeeper.c.GK_FWD_GRANTOR,
			["grantor"] = "3ffe:2501:200:3::1",
		},

		{
			["ip_prefix"] = "187.73.31.0/30",
			["action"] = gatekeeper.c.GK_FWD_GRANTOR,
			["grantor"] = "10.0.0.1",
		},

		{
			["ip_prefix"] = "187.73.32.0/30",
			["action"] = gatekeeper.c.GK_DROP,
		},
	}

	local ret = gatekeeper.init_lpm(gk_conf, net_conf, fib_entries)
	if ret < 0 then
		error("Failed to initialize gk LPM table")
	end

	-- Setup the GK functional block.
	ret = gatekeeper.c.run_gk(net_conf, gk_conf)
	if ret < 0 then
		error("Failed to run gk block(s)")
	end

	return gk_conf, ggu_lcore
end
