--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--
module("luci.controller.wifimedia.advance", package.seeall)
function index()
	entry( { "admin", "services", "advance" }, cbi("wifimedia_module/advance"), _("Advanced"),      10)
end