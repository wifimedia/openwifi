#!/bin/sh
# Copyright © 2017 Wifimedia.vn.
# All rights reserved.

. /sbin/wifimedia/variables.sh

diag_file=/tmp/diagnostics_ip #store data ip diagnostics from server monitor
touch $diag_file
touch /tmp/ports
touch /tmp/client_connect_wlan
touch /tmp/diagnostics_log
touch /tmp/client_data
#>/dev/null 2>&1
#[ -z STRING ] means: if STRING is NULL then return TRUE (0)
#[ -n STRING ] means: if STRING is not NULL then return TRUE (0)
ip_public(){
	PUBLIC_IP=`wget http://ipecho.net/plain -O - -q ; echo`
	echo $PUBLIC_IP
}

wr940v5() { #checking internet

	#check gateway
	ping -c 2 "$gateway" > /dev/null
	if [ $? -eq "0" ];then
		echo timer >/sys/devices/platform/leds-gpio/leds/tp-link:*:qss/trigger
	else
		echo none >/sys/devices/platform/leds-gpio/leds/tp-link:*:qss/trigger
	fi
	
	#checking internet
	ping -c 2 "8.8.8.8" > /dev/null
	if [ $? -eq "0" ];then
		echo timer >/sys/devices/platform/leds-gpio/leds/tp-link:*:wan/trigger
	else
		echo none >/sys/devices/platform/leds-gpio/leds/tp-link:*:wan/trigger
	fi

}

wr940v6() { #checking internet

	#check gateway
	ping -c 2 "$gateway" > /dev/null
	if [ $? -eq "0" ];then
		echo timer >/sys/devices/platform/leds-gpio/leds/tp-link:orange:diag/trigger
	else
		echo none >/sys/devices/platform/leds-gpio/leds/tp-link:orange:diag/trigger
		echo 1 >/sys/devices/platform/leds-gpio/leds/tp-link:orange:diag/brightness
	fi
	
	#checking internet
	ping -c 2 "8.8.8.8" > /dev/null
	if [ $? -eq "0" ];then
		echo timer >/sys/devices/platform/leds-gpio/leds/tp-link:blue:wan/trigger
	else
		echo none >/sys/devices/platform/leds-gpio/leds/tp-link:blue:wan/trigger
	fi
}

#ip=`nslookup $dnsctl | grep 'Address' | grep -v '127.0.0.1' | grep -v '8.8.8.8' | grep -v '0.0.0.0'|grep -v '::' | awk '{print $3}'`#

checking (){
	model=$(cat /proc/cpuinfo | grep 'machine' | cut -f2 -d ":" | cut -b 10-50 | tr ' ' '_')
	if [ "$model" == "TL-WR940N_v6" ];then
		wr940v6
	fi	
	if [ "$(cat /proc/meminfo | grep 'MemFree:' | awk '{print $2}')" -lt 5000 ]; then
		echo "Clear Cach"
		free && sync && echo 3 > /proc/sys/vm/drop_caches && free
	fi
	source /lib/functions/network.sh ; if network_get_ipaddr addr "wan"; then echo "WAN: $addr" >/tmp/ipaddr; fi
	#pidhostapd=`pidof hostapd`
	#if [ -z $pidhostapd ];then echo "Wireless Off" >/tmp/wirelessstatus;else echo "Wireless On" >/tmp/wirelessstatus;fi
}
start_cfg(){

touch /tmp/reboot_flag
touch /tmp/network_flag
touch /tmp/cpn_flag
touch /tmp/scheduled_flag
touch /tmp/clientdetect
local key
local value
cat $response_file | while read line ; do
	key=$(echo $line | cut -f 1 -d =)
	value=$(echo $line | cut -f 2- -d = | sed 's/"//g')
	
	#Cau hinh hostname
	if [ "$key" = "device.hostname" ];then
		uci set system.@system[0].hostname="$value"
		echo $value
	#Mat khau thiet bi	
	elif [ "$key" = "device.passwd" ];then
		echo -e "$value\n$value" | passwd root
	#Reboot device	
	elif [ "$key" = "device.reboot" ];then
		echo $value >/tmp/reboot_flag
	#Reset defaults	
	elif [ "$key" = "device.factoryreset" ];then
		if [ "$value" =  "1" ];then
			jffs2reset -y && reboot
		fi	
	#Cau hinh wireless 2.4
	elif [ "$key" = "wireless.radio2G.enable" ];then
		echo 1 >/tmp/network_flag
		uci set wireless.radio0.disabled="$value"
		echo $value
	elif [ "$key" = "wireless.radio2G.channel" ];then
		uci set wireless.radio0.channel="$value"
	elif [ "$key" = "wireless.radio2G.htmode" ];then
		value=$(echo $value | tr a-z A-Z)
		uci set wireless.radio0.htmode="$value"
	elif [ "$key" = "wireless.radio2G.txpower" ];then
		uci set wireless.radio0.txpower="$value"
	elif [ "$key" = "wireless.ssid2G" ];then
		uci set wireless.default_radio0.ssid="$value"
	elif [ "$key" = "wireless.passwd2G" ];then
		if [ "$value" = "" ];then
			uci set wireless.default_radio0.key=""
			uci set wireless.default_radio0.encryption="none"
		else
			uci set wireless.default_radio0.key="$value"
			uci set wireless.default_radio0.encryption="psk2"
		fi
	#chuyen dung chuan cache	
	elif [ "$key" = "wireless.okc2G" ];then
			uci set wireless.default_radio0.rsn_preauth="$value"
			uci delete wireless.default_radio0.ieee80211r >/dev/null 2>&1
			uci delete wireless.default_radio0.ft_over_ds >/dev/null 2>&1
			uci delete wireless.default_radio0.ft_psk_generate_local >/dev/null 2>&1
	#Chuyen dung 802.1R	
	elif [ "$key" = "wireless.ft2G" ];then
		if [ "$value" =  "1" ];then
			uci delete wireless.default_radio0.rsn_preauth >/dev/null 2>&1
			uci set wireless.default_radio0.ieee80211r="1"
			uci set wireless.default_radio0.ft_over_ds="1"
			uci set wireless.default_radio0.ft_psk_generate_local="1"
		fi	
	##Map SSID to net/plain LAN or WAN	
	elif [ "$key" = "wireless.network2G" ];then
		uci set wireless.default_radio0.network="$value"
	#Set Max Client	
	elif [ "$key" = "wireless.maxclients2G" ];then
		uci set wireless.default_radio0.maxassoc="$value"
	##Cau hinh switch 5 port		
	elif [ "$key" = "network.switch" ];then
		echo 1 >/tmp/network_flag
		uci set wireless.@wifi-iface[0].network="wan"
		uci set wifimedia.@switchmode[0].switch_port="$value"		
		if [ "$value" = "1" ];then
			uci delete network.lan
			uci set network.wan.proto="dhcp"
			uci set network.wan.ifname="eth0 eth1.1"
		else
			uci set network.lan="interface"
			uci set network.lan.proto="static"
			uci set network.lan.ipaddr="172.16.99.1"
			uci set network.lan.netmask="255.255.255.0"
			uci set network.lan.type="bridge"
			uci set network.lan.ifname="eth1.1"
			uci set dhcp.lan.force="1"
			uci set dhcp.lan.netmask="255.255.255.0"
			uci del dhcp.lan.dhcp_option
			uci add_list dhcp.lan.dhcp_option="6,8.8.8.8,8.8.4.4"				
			uci set network.wan.ifname="eth0"
		fi
	#Cu hinh IP LAN
	elif [ "$key" = "network.lan.static" ];then
		echo 1 >/tmp/network_flag
		uci delete network.lan >/dev/null 2>&1
		uci set network.lan="interface"
		uci set network.lan.type="bridge"	
		uci set network.lan.ifname="eth1.1"
		if [ "$value" = "1" ];then ##Static 
			uci set network.lan.proto="static"	
		else ##DHCP Client nhan IP
			uci set network.lan.proto="dhcp"	
		fi
	elif [  "$key" = "network.lan.ip" ];then
		uci set network.lan.ipaddr="$value"
	elif [  "$key" = "network.lan.subnetmask" ];then
		uci set network.lan.netmask="$value"
	elif [  "$key" = "network.lan.gateway" ];then
		uci set network.lan.gateway="$value"		
	elif [  "$key" = "network.lan.dns" ];then
		value=$(echo $value | sed 's/,/ /g')
		uci set network.lan.dns="$value"		
	###WAN config
	elif [ "$key" = "network.wan.static" ];then
		echo 1 >/tmp/network_flag
		uci delete network.wan >/dev/null 2>&1
		uci set network.wan="interface"
		uci set network.wan.type="bridge"	
		uci set network.wan.ifname="eth0"				
		if [ "$value" = "1" ];then ##Static 
			uci set network.wan.proto="static"
		else ##DHCP Client nhan IP
			uci set network.wan.proto="dhcp"	
		fi
	elif [  "$key" = "network.wan.ip" ];then
		uci set network.wan.ipaddr="$value"
	elif [  "$key" = "network.wan.subnetmask" ];then
		uci set network.wan.netmask="$value"
	elif [  "$key" = "network.wan.gateway" ];then
		uci set network.wan.gateway="$value"		
	elif [  "$key" = "network.wan.dns" ];then
		value=$(echo $value | sed 's/,/ /g')
		uci set network.wan.dns="$value"		
	##Cau hinh DHCP
	elif [  "$key" = "network.dhcp.start" ];then
		uci set dhcp.lan.start="$value"
	elif [  "$key" = "network.dhcp.limit" ];then
		uci set dhcp.lan.limit="$value"
	elif [  "$key" = "network.dhcp.leasetime" ];then
		uci set dhcp.network.leasetime="$value"
	elif [  "$key" = "detectclient.uri" ];then
		uci set wifimedia.@heartbeat[0].uri="$value"
	elif [  "$key" = "heartbeat.uri" ];then
		uci set wifimedia.@heartbeat[0].heartbeat_uri="$value"			
	#Cau hinh Captive Portal
	elif [  "$key" = "cpn.enable" ];then
		echo $value >/tmp/cpn_flag
		uci set nodogsplash.@nodogsplash[0].enabled="$value"
		uci set wifimedia.@nodogsplash[0].enable_cpn="$value"
		uci set nodogsplash.@nodogsplash[0].gatewayinterface="br-lan"
		uci set wifimedia.@nodogsplash[0].network="lan"		
	elif [  "$key" = "cpn.domain" ];then
		uci set wifimedia.@nodogsplash[0].domain="$value"
	elif [  "$key" = "cpn.walledgarden" ];then
		value=$(echo $value | sed 's/,/ /g')
		uci set wifimedia.@nodogsplash[0].preauthenticated_users="$value"
	#Network
	#elif [  "$key" = "cpn.network" ];then
	# uci set wifimedia.@nodogsplash[0].network="$value"		
	elif [  "$key" = "cpn.fb" ];then
		uci set wifimedia.@nodogsplash[0].facebook="$value"
	elif [  "$key" = "cpn.dhcpextenal" ];then
		uci set wifimedia.@nodogsplash[0].dhcpextension="$value"
		uci commit
		/sbin/wifimedia/captive_portal.sh dhcp_extension
	#Cau hinh auto reboot
	elif [  "$key" = "scheduletask.enable" ];then
		echo $value >/tmp/scheduled_flag
	elif [  "$key" = "scheduletask.hours" ];then
		uci set scheduled.@times[0].hour="$value"
	elif [  "$key" = "scheduletask.minute" ];then
		uci set scheduled.@times[0].minute="$value"
	elif [ "$key" =  "network.diagnostics" ]; then
		value=$(echo $value | sed 's/,/ /g')
		echo $value >$diag_file		
	fi
##
done	
uci commit

if [ $(cat /tmp/cpn_flag) -eq 1 ]; then
	echo "Config & Start Captive Portal"
	/sbin/wifimedia/captive_portal.sh config_captive_portal
	/etc/init.d/nodogsplash enable
	echo '*/10 * * * * /sbin/wifimedia/captive_portal.sh _nextify_service'>/etc/crontabs/nds
	/etc/init.d/cron restart
	rm /tmp/cpn_flag
else
  echo "Stop Captive Portal"
  /etc/init.d/nodogsplash disable
  echo ''>/etc/crontabs/nds
  /etc/init.d/firewall restart
  /etc/init.d/cron restart
  #service firewall restart
fi

if [ $(cat /tmp/network_flag) -eq 1 ]; then
	wifi down && wifi up
	/etc/init.d/network restart
	rm /tmp/network_flag
	echo "WIFI Online"
fi

if [ $(cat /tmp/reboot_flag) -eq 1 ]; then
	echo "restarting the node"
	 sleep 5 && reboot
fi	
}

_boot(){
	checking
	action_lan_wlan
	_lic
}

_lic(){
	if [ $check == "Activated" ];then
	  exit;
	else
	  echo "Activate"
	fi
	while true; do
    	ping -c3 -W1 8.8.8.8 >/dev/null
    	if [ ${?} -eq 0 ]; then
      	  	break
   	else
        	sleep 1
    	fi
	done
	license_srv
}

_nds(){ #Status Captive Portal
	nodogsplash=`pidof nodogsplash`
	if [ -z $nodogsplash ];then
		_cpn="Offline"
		echo $_cpn
		
	else
		_cpn="Online"
		echo $_cpn
	fi
}

srv(){
	token
	monitor_port
	heartbeat
	ip_public
	_nds
	diagnostics
	wget -q --post-data="token=${token}&gateway_mac=${global_device}&isp=${PUBLIC_IP}&ip_wan=${ip_wan}&ip_lan=${ip_lan}&diagnostics=${diagnostics_resulte}&ports_data=${ports_data}&mac_clients=${client_connect_wlan}&number_client=${NUM_CLIENTS}&ip_opvn=${ip_opvn}&captive_portal=${_cpn}&hardware=${model_hardware}" "$link_config$_device" -O $response_file

	#echo "Token "$token
	#echo "AP MAC "$global_device
	#echo "mac_clients "$client_connect_wlan
	#echo "ports_data "$ports_data
	curl_result=$?
	curl_data=$(cat $response_file)
	if [ "$curl_result" -eq "0" ]; then
		echo "Checked in to the dashboard successfully,"
	
		if grep -q "." $response_file; then
			echo "we have new settings to apply!"
		else
			echo "we will maintain the existing settings."
			exit
		fi	
	else
		logger "WARNING: Could not checkin to the dashboard."
		echo "WARNING: Could not checkin to the dashboard."
		exit
	fi
	start_cfg	
}
token(){
	#token = sha256(mac+secret)
	secret="(C)WifiMedia2019"
	mac_device=`ifconfig eth0 | grep 'HWaddr' | awk '{ print $5 }'| sed 's/:/-/g'`
	key=${mac_device}${secret}
	token=$(echo -n $(echo $key) | sha256sum | awk '{print $1}')
}

diagnostics(){
	ip=`cat $diag_file`

	for i in $ip; do
		ping -c 3 "$i" >/dev/null
		if [ $? -eq "0" ];then
			echo $i":Success" >>/tmp/diagnostics_log
		else
			echo $i":False" >>/tmp/diagnostics_log
		fi
	done
	diagnostics_resulte=$(cat /tmp/diagnostics_log | xargs | sed 's/ /;/g')
	rm /tmp/diagnostics_log
	rm $diag_file
}

monitor_port(){
	swconfig dev switch0 show |  grep 'link'| awk '{print $2, $3}' |tail -4|head -5| while read line;do
		echo "$line," >>/tmp/monitor_port
	done
	#ports_data=$(cat /tmp/monitor_port | xargs| sed 's/,/;/g' | sed 's/ port:/ /g' | sed 's/ link:/:/g' )
	ports=$(cat /tmp/monitor_port | xargs| sed 's/,/;/g' | sed 's/ link:/:/g'| sed 's/port:1://g'| sed 's/port:2://g'| sed 's/port:3://g'| sed 's/port:4://g' )
	echo $ports >/tmp/ports
	var1=`cat /tmp/ports`
	var2='4 3 2 1'
	set -- $var1
	for j in $var2;do
		echo "$j:$1" >>/tmp/tmp_port
		shift
	done
	ports_data=$(cat /tmp/tmp_port|xargs )
	echo $ports_data
	rm /tmp/monitor_port
    rm /tmp/tmp_port
}

heartbeat(){ #Heartbeat Nextify
	get_client_connect_wlan
	_get_server
	_post_clients
}

_post_clients(){ #$global_device: aa:bb:cc:dd:ee:ff
  if [ -n "$uri" ];then
		wget -q --post-data="clients=${client_data}&gateway_mac=${global_device}&number_client=${NUM_CLIENTS}" $uri -O /dev/null #http://api.nextify.vn/clients_around
  fi	
}

_get_server(){ # Connect to server Nextify
	if [ -n "$heartbeat_uri" ];then
		MAC=$(ifconfig eth0 | grep 'HWaddr' | awk '{ print $5 }')
		UPTIME=$(awk '{printf("%d:%02d:%02d:%02d\n",($1/60/60/24),($1/60/60%24),($1/60%60),($1%60))}' /proc/uptime)
		RAM_FREE=$(grep -i 'MemFree:'  /proc/meminfo | cut -d':' -f2 | xargs)
		wget -q --timeout=3 \
			 "$heartbeat_uri?mac=${MAC}&uptime=${UPTIME}&num_clients=${NUM_CLIENTS}" \
			 -O /dev/null
	fi		 
}

get_client_connect_wlan(){
	local _url=$1
	NEWLINE_IFS='
'
	OLD_IFS="$IFS"; IFS=$NEWLINE_IFS
	signal=''
	host=''
	mac=''
	touch /tmp/client_connect_wlan
	for iface in `iw dev | grep Interface | awk '{print $2}'`; do
		for line in `iwinfo $iface assoclist`; do
			if echo "$line" | grep -q "SNR"; then
				if [ -f /etc/ethers ]; then
					mac=$(echo $line | awk '{print $1}' FS=" ")
					host=$(awk -v MAC=$mac 'tolower($1)==MAC {print $1}' FS=" " /etc/ethers)
					signal=$(echo $line | awk '{print $2 $3}' FS=" ")
					data=";$mac"
					echo $data >>/tmp/client_connect_wlan
					echo "$mac;$signal">>/tmp/client_data
				fi
			fi
		done
	done
	IFS="$OLD_IFS"
	client_connect_wlan=$(cat /tmp/client_connect_wlan | xargs| sed 's/;//g'| tr a-z A-Z)
	client_data=`cat /tmp/client_data`
	NUM_CLIENTS=$(cat /tmp/client_connect_wlan | wc -l)
	rm /tmp/client_connect_wlan
	rm /tmp/client_data
}

action_lan_wlan(){ #$_device: aa-bb-cc-dd-ee-ff
	find_mac_gateway=/tmp/blacklist
	echo "" > $find_mac_gateway
	wget -q "${blacklist}" -O $find_mac_gateway
	curl_result=$?
	if [ "${curl_result}" -eq 0 ]; then
		cat "$find_mac_gateway" | while read line ; do
			if [ "$(echo $line | grep $_device)" ] ;then
				wifi down
				ifdown lan
			fi
		done	
	fi
}

license_srv() {
	###MAC WAN:WR940NV6 --Ethernet0 OPENWRT19
	#$_device: aa-bb-cc-dd-ee-ff
	echo "" > $licensekey
	wget -q "${code_srv}" -O $licensekey
	curl_result=$?
	if [ "${curl_result}" -eq 0 ]; then
		if grep -q "." $licensekey; then
			cat "$licensekey" | while read line ; do
				if [ "$(echo $line | grep $_device)" ] ;then
					#Update License Key
					uci set wifimedia.@hash256[0].wfm="$(cat /etc/opt/license/wifimedia)"
					uci commit wifimedia
					echo "Activated" >/etc/opt/license/status
					license_local
				fi
			done	
		fi
	fi
}

license_local() {
	first_time=$(cat /etc/opt/first_time.txt)
	timenow=$(date +"%s")
	diff=$(expr $timenow - $first_time)
	days=$(expr $diff / 86400)
	diff=$(expr $diff \% 86400)
	hours=$(expr $diff / 3600)
	diff=$(expr $diff \% 3600)
	min=$(expr $diff / 60)

	#uptime="${days}"
	time=$(uci -q get wifimedia.@wireless[0].time)
	time1=${days}
	uptime="${time:-$time1}"
	#uptime="${$(uci get license.active.time):-${days}}"
	#uptime="${days}d:${hours}h:${min}m"
	status=/etc/opt/wfm_status
	lcs=/etc/opt/wfm_lcs
	if [ "$(uci -q get wifimedia.@hash256[0].wfm)" == "$(cat /etc/opt/license/wifimedia)" ]; then
		echo "Activated" >/etc/opt/license/status
		rm $lcs >/dev/null 2>&1
	else
		echo "Not Activated" >/etc/opt/license/status
	fi
	if [ "$uptime" -gt 15 ]; then #>15days
		if [ "$(uci -q get wifimedia.@hash256[0].wfm)" == "$(cat /etc/opt/license/wifimedia)" ]; then
			uci set wireless.radio0.disabled="0"
			uci commit wireless
			wifi
			echo "Activated" >/etc/opt/license/status
			rm $lcs >/dev/null 2>&1
		else
			echo "Not Activated" >/etc/opt/license/status
			uci set wireless.radio0.disabled="1"
			uci commit wireless
			wifi down
		fi
	fi
}

rssi() {
if [ $rssi_on == "1" ];then
	level_defaults=-80
	level=$(uci -q get wifimedia.@wireless[0].level)
	level=${level%dBm}
	LOWER=${level:-$level_defaults}
	#echo $LOWER	
	dl_time=$(uci -q get wifimedia.@wireless[0].delays)
	dl_time=${dl_time%s}
	ban_time=$(expr $dl_time \* 1000)
	touch /tmp/denyclient
	chmod a+x /tmp/denyclient
	NEWLINE_IFS='
'
	OLD_IFS="$IFS"; IFS=$NEWLINE_IFS
	signal=''
	host=''
	mac=''

	for iface in `iw dev | grep Interface | awk '{print $2}'`; do
		for line in `iw $iface station dump`; do
			if echo "$line" | grep -q "Station"; then
				if [ -f /etc/ethers ]; then
					mac=$(echo $line | awk '{print $2}' FS=" ")
					host=$(awk -v MAC=$mac 'tolower($1)==MAC {print $2}' FS=" " /etc/ethers)
				fi
			fi
			if echo "$line" | grep -q "signal:"; then
				signal=`echo "$line" | awk '{print $2}'`
				#echo "$mac (on $iface) $signal $host"
				if [ "$signal" -lt "$LOWER" ]; then
					#echo $MAC IS $SNR - LOWER THAN $LOWER DEAUTH THEM
					echo "ubus call hostapd.$iface "del_client" '{\"addr\":\"$mac\", \"reason\": 1, \"deauth\": True, \"ban_time\": $ban_time}'" >>/tmp/denyclient
				fi
			fi
		done
	done
	IFS="$OLD_IFS"
	/tmp/denyclient
	echo "#!/bin/sh" >/tmp/denyclient
fi #END RSSI
}
"$@"
