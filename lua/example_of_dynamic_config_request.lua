-- TODO Add examples for other operations. For example:
-- Functions to add/del/list the GK FIB entries.
-- Functions to list the ARP table.
-- Functions to list the ND table.
-- Functions to process the GT policies.
-- ......

local dylib = require("dylib")
local ffi = require("ffi")

local dyc = gatekeeper.c.get_dy_conf()

-- Setup Grantor Prefixes.
local ret = dylib.c.add_fib_entry("128.197.40.100/24",
	dylib.c.GK_FWD_GATEWAY_BACK_NET, "10.0.1.254", dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

-- Setup Prefixes that need to forward to the back network.
ret = dylib.c.add_fib_entry("187.73.40.0/30",
	dylib.c.GK_FWD_GRANTOR, "128.197.40.100", dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.del_fib_entry("187.73.40.0/30", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("128.197.40.100/32", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("128.197.40.100/24", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("10.0.1.254/32", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

return "gk: successfully processed all the FIB entries\n"
