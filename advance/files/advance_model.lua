--[[
LuCI - Lua Configuration Interface
Copyright 2014 dungtd8x <dungtd8x@gmail.com>
]]--

local sys = require "luci.sys"
local fs = require "nixio.fs"
local uci = require "luci.model.uci".cursor()
local wfm_lcs = fs.access("/etc/opt/wfm_lcs")
local license = fs.access("/etc/opt/first_time.txt")
local next_net = luci.util.exec("uci -q get network.nextify")
local detect_5g = luci.util.exec("uci -q get wireless.radio0.hwmode")
m = Map("wifimedia", "")
m.apply_on_parse = true
function m.on_apply(self)
	if license then
		luci.sys.call("env -i /sbin/wifimedia/controller.sh license_local >/dev/null")
	end
	--luci.sys.call("env -i /sbin/wifimedia/controller_local.sh local_config >/dev/null")
	luci.sys.call("env -i /bin/ubus call network reload >/dev/null 2>/dev/null")
	--luci.http.redirect(luci.dispatcher.build_url("admin","wifimedia","advance"))
end

s = m:section(TypedSection, "wireless","")
s.anonymous = true
s.addremove = false
	
--RSSI--
s:tab("rssi",  translate("RSSI"))
	--s:taboption("rssi", Value, "pinginterval","Interval (s)").placeholder = "interval"
	rssi = s:taboption("rssi", Flag, "enable","Enable")
	rssi.rmempty = false
		function rssi.write(self, section, value)
			if value == self.enabled then
				luci.sys.call("env -i /etc/init.d/watchcat start >/dev/null")
				luci.sys.call("env -i /etc/init.d/watchcat enable >/dev/null")
			else
				luci.sys.call("env -i /etc/init.d/watchcat stop >/dev/null")
				luci.sys.call("env -i /etc/init.d/watchcat disable >/dev/null")
			end
			return Flag.write(self, section, value)
		end
		function rssi.remove() end
	--else 
	--	m.pageaction = false

	t = s:taboption("rssi", Value, "level","RSSI:","Received signal strength indication: Range:-60dBm ~ -90dBm")
	t.datatype = "min(-90)"
	--s:taboption("rssi",Value, "delays","Time Delays (s)").optional = false
	--t:depends({enable="1"})
--[[END RSSI]]--		
--License
if wfm_lcs then
	s:tab("license",  translate("Activation code"))
	wfm = s:taboption("license",Value,"wfm","Activation code")
	wfm.rmempty = true
end
--[[END LICENS]]--
return m
