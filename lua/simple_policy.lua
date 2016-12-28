local ffi = require("ffi")

local M = {}

--[[
This file defines simple policies without LPM for Grantor.

General format of the simple policies should be:
	IPv4 tables.
	IPv6 tables.

Here, I assume that each group has specific capability parameters,
including speed limit, expiration time, actions - DENY or ACCEPT, etc.
--]]

-- Function that set up the simple policy.
function M.setup_policy()

	local IPV4 = gatekeeper.c.IPV4

	-- Write simple policies below.

	local default = {
		["params"] = {
        		["expire_sec"] = 120,
        		["action"] = gatekeeper.c.GK_DECLINED,
    		},
	}

	local group1 = {
    		["params"] = {
        		["tx_rate_kb_sec"] = 20,
        		["cap_expire_sec"] = 20,
			["next_renewal_ms"] = 20,
			["renewal_step_ms"] = 20,
        		["action"] = gatekeeper.c.GK_GRANTED,
    		},
	}

	local groups = {
		[1] = group1,
		[255] = default,
	}

	local simple_policies = {
		[IPV4] = {
			{
				{
					["dest_port"] = 80,
    					["policy_id"] = groups[1],
				},
			},
		},
	}

	return simple_policies
end

-- Function that looks up the policy for the packet.
function M.lookup_policy(policies, fields)

	local mf = ffi.cast("struct gt_match_fields *", fields)

	for i, v in ipairs(policies[mf.proto]) do
		for j, g in ipairs(v) do
			if g["dest_port"] == mf.dest_port then
				return g["policy_id"]
			end
		end
	end

	return nil
end

return M
