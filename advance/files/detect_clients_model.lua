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
s:option(Value, "uri","Url")
clients = s:option( "basic",Flag, "enable","Enable")
clients.rmempty = false
function clients.write(self, section, value)
if value == self.enabled then
		luci.util.exec("echo '* * * * * /sbin/wifimedia/controller.sh _detect_clients' >/etc/crontabs/root")
		luci.util.exec("echo '* * * * * /sbin/wifimedia/controller.sh srv' >>/etc/crontabs/root")
		luci.util.exec("echo '* * * * * /sbin/wifimedia/controller.sh checking' >>/etc/crontabs/root && /etc/init.d/cron restart")	
	else
		luci.util.exec("echo '* * * * * /sbin/wifimedia/controller.sh srv' >/etc/crontabs/root")
		luci.util.exec("echo '* * * * * /sbin/wifimedia/controller.sh checking' >>/etc/crontabs/root && /etc/init.d/cron restart")	
	end
	return Flag.write(self, section, value)
end
		-- retain server list even if disabled
function clients.remove() end

return m
