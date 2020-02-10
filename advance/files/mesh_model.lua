--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--

local sys = require "luci.sys"
local fs = require "nixio.fs"
local uci = require "luci.model.uci".cursor()
m = Map("wifimedia", "")
m.apply_on_parse = true
function m.on_apply(self)
	--luci.sys.call("env -i /bin/ubus call network reload >/dev/null 2>/dev/null")
	luci.sys.call("env -i /bin/ubus call network restart >/dev/null 2>/dev/null")
end

s = m:section(TypedSection, "mesh","Mesh")
s.anonymous = true
s.addremove = false
s:option(Value, "mesh_id","Mesh ID")
network = s:taboption( "basic",ListValue, "network","Interface")
network:value("lan", "LAN")
network:value("wan", "WAN")
mesh_mode = s:option(Flag, "mesh","MeshPoint","")
mesh_mode.rmempty = false
		function mesh_mode.write(self, section, value)
			if value == self.enabled then
				luci.sys.call("uci commit")
				luci.sys.call("env -i /sbin/wifimedia/controller.sh _meshpoint")
			else
			    luci.sys.call("uci del wireless.MeshPoint")
				luci.sys.call("uci commit")		
			end
			return Flag.write(self, section, value)
		end
		function mesh_mode.remove() end
return m
