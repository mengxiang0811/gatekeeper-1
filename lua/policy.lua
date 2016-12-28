local gatekeeper = require("gatekeeper")
local ffi = require("ffi")

local policy_names = {
	"simple_policy",
	"lpm_policy",
}

local default = {
    	["params"] = {
        	["tx_rate_kb_sec"] = 10,
        	["cap_expire_sec"] = 10,
		["next_renewal_ms"] = 10,
		["renewal_step_ms"] = 10,
        	["action"] = gatekeeper.c.GK_GRANTED,
    	},
}

GLOBAL_POLICIES = {}

function setup_policy(socket, lcore)

	for key, value in ipairs(policy_names) do
		local policy_module = require(value)
		local policies = policy_module.setup_policy(socket, lcore)

		if policies ~= nil then
			GLOBAL_POLICIES[value] = policies
		end
	end
end

function lookup_policy(fields, policy)
	local mf = ffi.cast("struct gt_match_fields *", fields)
	local pl = ffi.cast("struct ggu_policy *", policy)
	local group = nil

	for key, value in ipairs(policy_names) do
		local policy_module = require(value)
		local g = policy_module.lookup_policy(
			GLOBAL_POLICIES[value], mf)

		if g ~= nil then
			group = g
			break
		end
	end

	if group == nil then group = default end

	pl.state = group["params"]["action"]

	if pl.state == gatekeeper.c.GK_DECLINED then
		pl.params.u.declined.expire_sec =
			group["params"]["expire_sec"]
	else
		pl.params.u.granted.tx_rate_kb_sec =
			group["params"]["tx_rate_kb_sec"]
		pl.params.u.granted.cap_expire_sec =
			group["params"]["cap_expire_sec"]
		pl.params.u.granted.next_renewal_ms =
			group["params"]["next_renewal_ms"]
		pl.params.u.granted.renewal_step_ms =
			group["params"]["renewal_step_ms"]
	end
end
