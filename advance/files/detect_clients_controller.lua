--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--
module("luci.controller.wifimedia.detect_clients", package.seeall)
function index()
	entry( { "admin", "services", "detect_clients" }, cbi("wifimedia_module/detect_clients"), _("Detect clients"),      15)
end
