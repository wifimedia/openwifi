--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--

local sys = require "luci.sys"
local fs = require "nixio.fs"
local uci = require "luci.model.uci".cursor()
m = Map("wifimedia", "")
m.apply_on_parse = true

s = m:section(TypedSection, "detect_clients","Wireless detect clients")
s.anonymous = true
s.addremove = false
s:option(Value, "uri","Sync server")
s:option(Value, "heartbeat_uri","Heartbeat uri")
return m
