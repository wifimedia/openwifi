#!/bin/sh

#Variable
NODOGSPLASH_CONFIG=/tmp/etc/nodogsplash.conf
PREAUTHENTICATED_ADDRS=/tmp/preauthenticated_addrs
PREAUTHENTICATED_ADDR_FB=/tmp/preauthenticated_addr_fb
PREAUTHENTICATED_RULES=/tmp/preauthenticated_rules
NEXTIFY_ADDRS=/tmp/nextify_addrs
NET_ID=`uci -q get wifimedia.@nodogsplash[0].network`
networkncpn=${NET_ID:-lan}
walledgadent=`uci -q get wifimedia.@nodogsplash[0].preauthenticated_users | sed 's/,/ /g'`
domain=`uci -q get wifimedia.@nodogsplash[0].domain`
domain_default=${domain:-portal.nextify.vn/splash}
#redirecturl=`uci -q get wifimedia.@nodogsplash[0].redirecturl`
#redirecturl_default=${redirecturl:-https://google.com.vn}
preauthenticated_users=`uci -q get wifimedia.@nodogsplash[0].preauthenticated_users` #Walled Gardent
maxclients=`uci -q get wifimedia.@nodogsplash[0].maxclients`
maxclients_default=${maxclients:-250}
preauthidletimeout=`uci -q get wifimedia.@nodogsplash[0].preauthidletimeout`
preauthidletimeout_default=${preauthidletimeout:-30}
authidletimeout=`uci -q get wifimedia.@nodogsplash[0].authidletimeout`
authidletimeout_default=${authidletimeout:-120}
sessiontimeout=`uci -q get wifimedia.@nodogsplash[0].sessiontimeout`
sessiontimeout_default=${sessiontimeout:-120}
std=`expr $sessiontimeout_default \* 60`
checkinterval=`uci -q get wifimedia.@nodogsplash[0].checkinterval`
checkinterval_default=${checkinterval:-10}
ctv=`expr $checkinterval_default \* 60`
https=`uci -q get wifimedia.@nodogsplash[0].https`
facebook=`uci -q get wifimedia.@nodogsplash[0].facebook`
MAC_E0=$(ifconfig eth0 | grep 'HWaddr' | awk '{ print $5 }')
nds_status=`uci -q get nodogsplash.@nodogsplash[0].enabled`
heartbeat_url=`uci -q get wifimedia.@nodogsplash[0].heartbeat`
ip_lan_gw=$(ifconfig br-lan | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1 }')
ip_hotspot_gw=$(ifconfig br-hotspot | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1 }')
inf=`uci -q get network.lan`
source /lib/functions/network.sh
config_captive_portal() {
	if [ $nds_status -eq 0 ];then
		/etc/init.d/nodogsplash stop
		/etc/init.d/firewall restart
		exit;
	else	

		#uci set nodogsplash.@nodogsplash[0].enabled='1'
		uci set nodogsplash.@nodogsplash[0].gatewayinterface="br-$networkncpn";	
		uci set nodogsplash.@nodogsplash[0].gatewayname="CPN";
		#uci set nodogsplash.@nodogsplash[0].redirecturl="$redirecturl_default";
		uci set nodogsplash.@nodogsplash[0].maxclients="$maxclients_default";
		uci set nodogsplash.@nodogsplash[0].preauthidletimeout="$preauthidletimeout_default";
		uci set nodogsplash.@nodogsplash[0].authidletimeout="$authidletimeout_default";
		#uci set nodogsplash.@nodogsplash[0].sessiontimeout="$std";
		uci set nodogsplash.@nodogsplash[0].sessiontimeout="$sessiontimeout_default";
		uci set nodogsplash.@nodogsplash[0].checkinterval="$ctv";
		# Whitelist IP
		for i in portal.nextify.vn portal.nextify.co static.nextify.vn nextify.vn crm.nextify.vn googletagmanager.com wifimedia.vn portal.wifioto.net wifioto.net ipecho.net $domain $walledgadent; do
			nslookup ${i} 8.8.8.8 2> /dev/null | \
				grep 'Address ' | \
				grep -v '127\.0\.0\.1' | \
				grep -v '8\.8\.8\.8' | \
				grep -v '0\.0\.0\.0' | \
				awk '{print $3}' | \
				grep -v ':' >> ${PREAUTHENTICATED_ADDRS}
		done

		###Facebook
		for i in facebook.com fbcdn-profile-a.akamaihd.net; do
			nslookup ${i} 8.8.8.8 2> /dev/null | \
				grep 'Address ' | \
				grep -v '127\.0\.0\.1' | \
				grep -v '8\.8\.8\.8' | \
				grep -v '0\.0\.0\.0' | \
				awk '{print $3}' | \
				grep -v ':' >> ${PREAUTHENTICATED_ADDR_FB}
		done

		###Read line file 
		uci del nodogsplash.@nodogsplash[0].users_to_router >/dev/null 2>&1
		uci del nodogsplash.@nodogsplash[0].authenticated_users >/dev/null 2>&1
		uci del nodogsplash.@nodogsplash[0].preauthenticated_users >/dev/null 2>&1
		uci add_list nodogsplash.@nodogsplash[0].authenticated_users="allow all" >/dev/null 2>&1
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow to 172.16.99.1" >/dev/null 2>&1
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow to 10.68.255.1" >/dev/null 2>&1
		uci commit
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow to $ip_hotspot_gw" >/dev/null 2>&1
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow to $ip_lan_gw" >/dev/null 2>&1
		if [ -z "$inf" ];then #neu khong co int thi
			uci set nodogsplash.@nodogsplash[0].gatewayinterface="br-hotspot"
			uci set wifimedia.@nodogsplash[0].network="hotspot"
			uci set wireless.default_radio0.network="hotspot"
		fi

		if network_get_ipaddr addr "wan"; then
			uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow to $addr"
		fi			
		while read line; do
			uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 80 to $(echo $line)"
			uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 443 to $(echo $line)"
		done <$PREAUTHENTICATED_ADDRS

		if [ "$facebook" == "1" ];then
			while read fb; do
				uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 80 to $(echo $fb)"
				uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 443 to $(echo $fb)"
			done <$PREAUTHENTICATED_ADDR_FB
		fi
		if [ "$https" == "1" ];then ##For ALL 443
			uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 443"
			#while read line; do
			#	uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 443 to $(echo $line)"
			#done <$PREAUTHENTICATED_ADDRS
		fi
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 22"
		#uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 80"
		#uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 443"
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow tcp port 53"
		uci add_list nodogsplash.@nodogsplash[0].preauthenticated_users="allow udp port 53"	
		uci add_list nodogsplash.@nodogsplash[0].users_to_router="allow tcp port 22"
		uci add_list nodogsplash.@nodogsplash[0].users_to_router="allow tcp port 53"
		uci add_list nodogsplash.@nodogsplash[0].users_to_router="allow udp port 53"
		uci add_list nodogsplash.@nodogsplash[0].users_to_router="allow udp port 67"
		uci add_list nodogsplash.@nodogsplash[0].users_to_router="allow tcp port 80"
		uci add_list nodogsplash.@nodogsplash[0].users_to_router="allow tcp port 443"	
		uci commit nodogsplash
		rm -f $PREAUTHENTICATED_ADDRS $PREAUTHENTICATED_ADDR_FB
		dhcp_extension
		wifi
		/etc/init.d/nodogsplash stop
		sleep 5
		/etc/init.d/nodogsplash start
	fi
	write_login
}

captive_portal_restart(){
	# Get status nodogsplash
	ndsctl status > /tmp/ndsctl_status.txt
	if [ ${?} -eq 0 ]; then
		echo "Nodogsplash running"
	else
		echo "Nodogsplash crash"
		# Nodogsplash crash
		while true; do
			ping -c1 -W1 8.8.8.8
			if [ ${?} -eq 0 ]; then
				break
			else
				sleep 1
			fi
		done
		 /etc/init.d/nodogsplash restart >/dev/null
	fi
}

_nextify_service(){

    domain_nextify=`echo $domain_default | cut -c 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17`
	flag_dns=/tmp/nextify_dns		 
	wget -q --timeout=3 \
		"http://api.nextify.co/check_portal?site=$domain_nextify" -O $flag_dns
	if [ $? -eq "0" ];then
		_flag=`cat $flag_dns`
		if [ $_flag -eq 1 ];then
			#dich vu nextify dang chay
			ndsctl status > /tmp/ndsctl_status.txt
			if [ $? -eq 0 ]; then
				#nodogsplash dang chay
				exit;
			else
				#nodogsplash khong chay thi start lai
				uci set nodogsplash.@nodogsplash[0].enabled='1'
				uci set wifimedia.@nodogsplash[0].enable_cpn='1'
				uci commit
				/etc/init.d/nodogsplash start
			fi
		else
		#dich vu next bi tat thi cho tat luon chuong trinh nodogsplash
		_disable_captive
		fi
	else
		_disable_captive	
	fi
}

_disable_captive() {
	nds_enable=$(uci get nodogsplash.@nodogsplash[0].enabled)
    if [ $nds_enable == "0" ];then
    	exit
    fi
    uci set wifimedia.@nodogsplash[0].enable_cpn='0'
	uci set nodogsplash.@nodogsplash[0].enabled='0'
	uci commit
	/etc/init.d/firewall restart
}
heartbeat(){
	captive_portal_restart
}

get_captive_portal_clients() {
     #trap "error_trap get_captive_portal_clients '$*'" $GUARD_TRAPS
     local line
     local key
     local value
     local ip_address=
     local mac_address=
     local connection_timestamp=
     local activity_timestamp=
     local traffic_download=
     local traffic_upload=
	 local global_device=`ifconfig eth0 | grep 'HWaddr' | awk '{ print $5 }'`
     # erzwinge eine leere Zeile am Ende fuer die finale Ausgabe des letzten Clients
     (ndsctl clients; echo) | while read line; do
         key=$(echo "$line" | cut -f 1 -d =)
         value=$(echo "$line" | cut -f 2- -d =)
         [ "$key" = "ip" ] && ip_address="$value"
         [ "$key" = "mac" ] && mac_address="$value"
         [ "$key" = "added" ] && connection_timestamp="$value"
         [ "$key" = "active" ] && activity_timestamp="$value"
         [ "$key" = "downloaded" ] && traffic_download="$value"
         [ "$key" = "uploaded" ] && traffic_upload="$value"
         if [ -z "$key" -a -n "$ip_address" ]; then
             # leere Eingabezeile trennt Clients: Ausgabe des vorherigen Clients
             printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
                 "$ip_address" "$mac_address" "$connection_timestamp" \
                 "$activity_timestamp" "$traffic_download" "$traffic_upload"
	     data=";$mac_address"
	     echo $data >>/tmp/captive_portal_clients
             ip_address=
             mac_address=
             connection_timestamp=
             activity_timestamp=
             traffic_download=
             traffic_upload=
         fi
    done
 }

write_login(){

	#write file splash
	echo '<!doctype html>
	<html lang="en">
	  <head>
		  <meta charset="utf-8">
		  <title>$Captive Portal</title>
	  </head>
	  <body>
		  <form id="info" method="POST" action="//'$domain_default'">
			  <input type="hidden" name="gateway_mac" value="'$MAC_E0'">
			  <input type="hidden" name="client_mac" value="$clientmac">
			  <input type="hidden" name="num_clients" value="$nclients">
			  <input type="hidden" name="uptime" value="$uptime">
			  <input type="hidden" name="auth_target" value="$authtarget">
		  </form>
		  <script>
			  document.getElementById("info").submit();
		  </script>
	  </body>
	</html>' >/etc/nodogsplash/htdocs/splash.html

	#write file infoskel
	echo '<!doctype html>
	<html lang="en">
		<head>
			<meta charset="utf-8">
			<title>Whoops...</title>
			<meta http-equiv="refresh" content="0; url="//'$domain'">
			<style>
				html {
					background: #F7F7F7;
				}
			</style>
		</head>
		<body></body>
	</html>' >/etc/nodogsplash/htdocs/status.html
}

dhcp_extension(){
	uci del network.local.network
	uci set network.local=interface
	uci set network.local.proto="relay"
	dhcpextenition=`uci -q get wifimedia.@nodogsplash[0].dhcpextension`
	if [ $dhcpextenition -eq 1 ];then
		if [ $networkncpn = "hotspot" ];then
			uci set network.local.ipaddr=$ip_hotspot_gw
		else
			uci set network.local.ipaddr=$ip_lan_gw
		fi
		uci add_list network.local.network=$networkncpn
		uci set dhcp.$networkncpn.ignore='1'
		uci set wireless.default_radio0.network=$networkncpn
		uci set wireless.default_radio1.network=$networkncpn		
		uci add_list network.local.network='wan'
	else
		uci set wireless.default_radio0.network=$networkncpn
		uci set dhcp.$networkncpn.ignore='0'
	fi
	uci commit && wifi up
}

"$@"
