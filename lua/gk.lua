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

	local front_net_prefix = "10.0.0.1/24"
	local front_net_prefix6 = "2001:db8::1/32"

	local back_net_prefix = "10.0.0.2/24"
	local back_net_prefix6 = "2001:db8::2/32"

	-- Setup the GK functional block.
	ret = gatekeeper.c.run_gk(
		front_net_prefix, front_net_prefix6,
		back_net_prefix, back_net_prefix6,
		net_conf, gk_conf)
	if ret < 0 then
		error("Failed to run gk block(s)")
	end

	return gk_conf, ggu_lcore
end
