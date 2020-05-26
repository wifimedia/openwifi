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
--[Auto config AP]--
s:tab("groups","Groups config")
cfg_en = s:taboption("groups",Flag,"cfg_enable")
ssid = s:taboption("groups",value,"essid","ESSID")
ssid:depends({cfg_enable=1})

cfg_mod = s:taboption("groups", ListValue, "mode", "MODE")
cfg_mod:value("ap", "AP")
cfg_mod:value("mesh","MESH")
cfg_mod:value("wds","WDS")
cfg_mod:depends({cfg_enable="1"})

cfg_ch = s:taboption("groups", ListValue,"channel", "Channel")
local  channel = 1
while (channel < 13) do
	cfg_ch:value(channel, channel .. "")
	channel = channel + 1
end
cfg_ch.default = "6"
cfg_ch:depends({cfg_enable = "1"})

cfg__max = s:taboption("groups", Value, "maxassoc", "Connection Limit")
cfg__max:depends({cfg_enable="1"})

cfg_net = s:taboption("groups", ListValue, "Network")
cfg_net:value("wan", "WAN")
cfg_net:value("lan", "LAN")
cfg_net:depends({cfg_enable="1"})

cfg_enc = s:taboption("groups", ListValue, "encrypt", "Wireless Security")
cfg_enc:value("","No Encryption")
cfg_enc:value("encryption","WPA-PSK/WPA2-PSK")
cfg_enc:depends({cfg_enable="1"})

--password
cfg_passwd = s:taboption("groups",Value,"password","Password")
cfg_passwd.datatype = "wpakey"
cfg_passwd.rmempty = true
cfg_passwd.password = true
cfg_passwd:depends({cfg_enable="1"})
--roaming
cfg_r = s:taboption("groups",ListValue, "ft", "Fast Roaming")
cfg_r:value("rsn_preauth","Fast-Secure Roaming")
cfg_r:value("ieee80211r","Fast Roaming 802.11R")
cfg_r:depends({encrypt="encryption"})

cfg_r_pmk = s:taboption("groups",Flag,"ft_psk_generate_local","Generate PMK Locally")
cfg_r_pmk:depends({ft="ieee80211r"})
cfg_r_pmk.rmempty = false

--isolation--
cfg_iso = s:taboption("groups",Flag, "isolation","AP Isolation")
cfg_iso.rmempty = false
cfg_iso:depends({cfg_enable="1"})

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
