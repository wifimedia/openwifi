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
	luci.sys.call("env -i /sbin/wifimedia/controller.sh _meshpoint >/dev/null")
end
s = m:section(TypedSection, "mesh","Mesh")
s.anonymous = true
s.addremove = false
s:option(Value, "mesh_id","Mesh ID")
network = s:option(ListValue, "network","Interface")
network:value("lan", "LAN")
network:value("wan", "WAN")
mesh_mode = s:option(Flag, "enable","MeshPoint","")
mesh_mode.rmempty = false
return m
