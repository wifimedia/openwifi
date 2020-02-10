--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--
module("luci.controller.wifimedia.switchmode", package.seeall)
function index()
	entry( { "admin", "services", "switchmode" }, cbi("wifimedia_module/switchmode"), _("Ethernet switch "),      15)
end
