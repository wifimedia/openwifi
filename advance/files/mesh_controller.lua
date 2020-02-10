--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--
module("luci.controller.wifimedia.mesh", package.seeall)
function index()
	entry( { "admin", "network", "mesh" }, cbi("wifimedia_module/mesh"), _("Mesh "),      15)
end
