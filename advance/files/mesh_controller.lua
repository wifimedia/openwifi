--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--
module("luci.controller.wifimedia.meshmode", package.seeall)
function index()
	entry( { "admin", "network", "meshmode" }, cbi("wifimedia_module/meshmode"), _("Mesh "),      15)
end
