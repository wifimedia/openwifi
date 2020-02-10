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
	--luci.http.redirect(luci.dispatcher.build_url("admin","wifimedia","advance"))
end

s = m:section(TypedSection, "switchmode","Ethernet Switch")
s.anonymous = true
s.addremove = false

switch_mode = s:option(Flag, "switch_port","All port LAN & WAN","")
switch_mode.rmempty = false
		function switch_mode.write(self, section, value)
			if value == self.enabled then
				luci.sys.call("uci delete network.lan")
				luci.sys.call("uci set network.wan.proto='dhcp'")
				luci.sys.call("uci set network.wan.ifname='eth0 eth1.1'")
				luci.sys.call("uci set wireless.@wifi-iface[0].network='wan'")
				luci.sys.call("uci commit")
			else
			    luci.sys.call("uci set network.lan='interface'")
				luci.sys.call("uci set network.lan.proto='static'")
				luci.sys.call("uci set network.lan.ipaddr='192.168.5.1'")
				luci.sys.call("uci set network.lan.netmask='255.255.255.0'")
				luci.sys.call("uci set network.lan.type='bridge'")
				luci.sys.call("uci set network.lan.ifname='eth1.1'")
				luci.sys.call("uci set dhcp.lan.force='1'")
				luci.sys.call("uci set dhcp.lan.netmask='255.255.255.0'")
				luci.sys.call("uci del dhcp.lan.dhcp_option")
				luci.sys.call("uci add_list dhcp.lan.dhcp_option='6,8.8.8.8,8.8.4.4'")				
				luci.sys.call("uci set network.wan.ifname='eth0'")
				luci.sys.call("uci set wireless.@wifi-iface[0].network='wan'")
				luci.sys.call("uci commit")		
			end
			return Flag.write(self, section, value)
		end
		function switch_mode.remove() end
return m
