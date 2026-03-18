/interface bridge
{{BRIDGE_LINES}}

/interface ethernet
set [ find default-name=ether1 ] comment=ICT
set [ find default-name=qsfp28-1-1 ] disabled=yes
set [ find default-name=qsfp28-1-2 ] disabled=yes
set [ find default-name=qsfp28-1-3 ] disabled=yes
set [ find default-name=qsfp28-1-4 ] disabled=yes
set [ find default-name=qsfp28-2-1 ] disabled=yes
set [ find default-name=qsfp28-2-2 ] disabled=yes
set [ find default-name=qsfp28-2-3 ] disabled=yes
set [ find default-name=qsfp28-2-4 ] disabled=yes
{{UPLINK_ETHERNET_LINES}}
{{OLT_ETHERNET_LINES}}
set [ find default-name=sfp28-12 ] auto-negotiation=no comment=exfo speed=10G-baseSR-LR

/interface vpls
{{VPLS_LINES}}

/interface vlan
add disabled=yes interface={{UPLINK_PRIMARY_PORT}} mtu={{UPLINK_PRIMARY_MTU}} name=vlan1017 vlan-id=1017

/interface bonding
{{OLT1_BONDING_LINE}}
{{OLT2_BONDING_LINE}}

/interface vlan
{{OLT1_VLAN_LINES}}
{{OLT2_VLAN_LINES}}

/ip dhcp-server option
add code=43 name=opt43 value=0x012d68747470733a2f2f6e61342e6e6f6b69616163732e6e6f6b69612e636f6d3a31373534372f6e6578746c696e6b020561646d696e030561646d696e

/ip dhcp-server option sets
add name=optset options=opt43

/ip pool
add name=cust ranges={{CGNAT_POOL_START}}-{{CGNAT_POOL_END}}
add name=cpe ranges={{CPE_POOL_START}}-{{CPE_POOL_END}}
add name=unauth ranges={{UNAUTH_POOL_START}}-{{UNAUTH_POOL_END}}

/port
set 0 name=serial0

{{BGP_INSTANCE_BLOCK}}

/routing bgp template
{{BGP_TEMPLATE_LINE}}

/routing ospf instance
add disabled=no name=default-v2 router-id={{ROUTER_ID}}

/routing ospf area
add area-id={{OSPF_AREA_ID}} disabled=no instance=default-v2 name={{OSPF_AREA_NAME}}

/snmp community
set [ find default=yes ] read-access=no
add addresses=::/0 name=FBZ1yYdphf

/system logging action
set 1 disk-file-count=3 disk-lines-per-file=10000
add name=syslog remote=142.147.116.215 src-address={{ROUTER_ID}} target=remote

/user group
set read policy="local,telnet,ssh,read,test,winbox,password,web,sniff,sensitive,api,romon,rest-api,!ftp,!reboot,!write,!policy"
add name=ENG policy="local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,rest-api"
add name=NOC policy="local,telnet,ssh,ftp,reboot,read,write,test,winbox,password,sniff,sensitive,!policy,!web,!api,!romon,!rest-api"
add name=LTE policy="local,telnet,ssh,reboot,read,write,test,winbox,password,sniff,sensitive,!ftp,!policy,!web,!api,!romon,!rest-api"
add name=DEVOPS policy="local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,rest-api"
add name=VOIP policy="local,telnet,ssh,read,test,winbox,sniff,!ftp,!reboot,!write,!policy,!password,!web,!sensitive,!api,!romon,!rest-api"
add name=STS policy="local,telnet,ssh,read,test,winbox,sniff,!ftp,!reboot,!write,!policy,!password,!web,!sensitive,!api,!romon,!rest-api"
add name=TECHSUPPORT policy="local,telnet,read,test,winbox,sniff,!ssh,!ftp,!reboot,!write,!policy,!password,!web,!sensitive,!api,!romon,!rest-api"
add name=INFRA policy="local,telnet,reboot,read,write,test,winbox,!ssh,!ftp,!policy,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api"
add name=INSTALL policy="local,telnet,reboot,read,write,test,winbox,!ssh,!ftp,!policy,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api"
add name=COMENG policy="local,telnet,ssh,reboot,read,write,test,winbox,sniff,!ftp,!policy,!password,!web,!sensitive,!api,!romon,!rest-api"
add name=INTEGRATIONS policy="local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,rest-api"
add name=IDO policy="local,telnet,ssh,reboot,read,write,test,winbox,password,sniff,sensitive,!ftp,!policy,!web,!api,!romon,!rest-api"
add name=CALLCENTER-WRITE policy="local,telnet,ssh,read,write,test,winbox,sniff,!ftp,!reboot,!policy,!password,!web,!sensitive,!api,!romon,!rest-api"

/interface bridge port
{{OLT1_BRIDGE_PORTS}}
add bridge=lan-bridge interface=ether1
{{OLT2_BRIDGE_PORTS}}

/ip neighbor discovery-settings
set discover-interface-list=!dynamic

/ip address
add address={{CPE_GATEWAY}}/{{CPE_PREFIX}} comment="CPE/Tower Gear" interface=lan-bridge network={{CPE_NETWORK_BASE}}
add address={{LOOPBACK_IP}} comment=loop0 interface=loop0 network={{LOOPBACK_IP}}
add address={{UNAUTH_GATEWAY}}/{{UNAUTH_PREFIX}} comment=UNAUTH interface=lan-bridge network={{UNAUTH_NETWORK_BASE}}
add address={{CGNAT_GATEWAY}}/{{CGNAT_PREFIX}} comment="CGNAT Private" interface=bridge1000 network={{CGNAT_NETWORK_BASE}}
{{OLT1_IP_LINE}}
add address={{CGNAT_PUBLIC}} comment="CGNAT Public" interface=nat-public-bridge network={{CGNAT_PUBLIC}}
{{OLT2_IP_LINE}}
{{UPLINK_IP_LINES}}

/ip dhcp-server
add address-pool=cust dhcp-option-set=optset interface=bridge1000 lease-time=10m name=server1 use-radius=yes

/ip dhcp-server network
add address={{CPE_NETWORK_BASE}}/{{CPE_PREFIX}} dns-server=142.147.112.3,142.147.112.19 gateway={{CPE_GATEWAY}} netmask={{CPE_PREFIX}}
add address={{UNAUTH_NETWORK_BASE}}/{{UNAUTH_PREFIX}} dns-server=142.147.112.3,142.147.112.19 gateway={{UNAUTH_GATEWAY}} netmask={{UNAUTH_PREFIX}}
add address={{CGNAT_NETWORK_BASE}}/{{CGNAT_PREFIX}} dhcp-option-set=optset dns-server=142.147.112.3,142.147.112.19 gateway={{CGNAT_GATEWAY}} netmask={{CGNAT_PREFIX}}

/ip dns
set servers=142.147.112.3,142.147.112.19

/ip firewall address-list
add address=142.147.112.3 list=NAT-EXEMPT-DST
add address=142.147.112.19 list=NAT-EXEMPT-DST
add address=107.178.15.0/27 list=NAT-EXEMPT-DST
add address=107.178.5.97 list=NAT-EXEMPT-DST
add address=69.53.224.0/19 list=NETFLIX
add address=108.175.32.0/20 list=NETFLIX
add address=192.173.64.0/18 list=NETFLIX
add address=198.38.96.0/19 list=NETFLIX
add address=198.45.48.0/20 list=NETFLIX
add address=208.75.76.0/22 list=NETFLIX
add address=24.220.183.0/24 list=NETFLIX
add address=216.168.119.0/24 list=NETFLIX
add address=23.246.0.0/20 list=NETFLIX
add address=173.246.157.0/24 list=NETFLIX
add address=37.77.184.0/23 list=NETFLIX
add address=64.140.112.0/24 list=NETFLIX
add address=66.97.254.0/24 list=NETFLIX
add address=185.2.223.0/24 list=NETFLIX
add address=107.178.15.4 list=Voip-Servers
add address={{UNAUTH_NETWORK_BASE}}/{{UNAUTH_PREFIX}} comment=UNAUTH list=bgp-networks
add address={{CGNAT_NETWORK_BASE}}/{{CGNAT_PREFIX}} comment=CGNAT_PRIVATE list=bgp-networks
add address={{CGNAT_PUBLIC}} comment=CGNAT_PUBLIC list=bgp-networks
add address=10.0.0.0/8 list=EOIP-ALLOW
add address=192.168.128.0/21 list=managerIP
add address=107.178.5.97 list=managerIP
add address=198.100.53.0/25 list=managerIP
add address=143.55.62.143 list=managerIP
add address=143.55.37.42 list=managerIP
add address=143.55.37.43 list=managerIP
add address=142.147.127.2 list=managerIP
add address=132.147.147.67 list=managerIP
add address=132.147.147.68 list=managerIP
add address=132.147.132.6 list=managerIP
add address=132.147.132.96 list=managerIP
add address=132.147.132.97 list=managerIP
add address=132.147.132.205 list=managerIP
add address=67.219.122.201 list=managerIP
add address=132.147.138.52 list=managerIP
add address=132.147.138.53 list=managerIP
add address=132.147.138.54 list=managerIP
add address=10.249.1.26 list=managerIP
add address=10.0.0.0/8 list=managerIP
add address=10.0.0.0/8 list=BGP-ALLOW
add address=143.55.35.47 list=SNMP
add address=107.178.15.15 list=SNMP
add address=107.178.15.162 list=SNMP
add address=142.147.112.4 list=SNMP
add address=142.147.124.26 list=SNMP
add address=107.178.5.97 list=SNMP
add address=52.128.51.70 list=SNMP
add address=52.128.51.80 list=SNMP
add address=67.219.126.240/28 list=SNMP
add address=198.100.53.120 list=SNMP
add address=143.55.62.143 list=SNMP
add address=132.147.138.2 list=SNMP
add address=132.147.138.0 list=SNMP
add address=132.147.138.6 list=SNMP
add address=132.147.138.23 list=SNMP
add address=132.147.138.29 list=SNMP
add address=132.147.138.30 list=SNMP
add address=132.147.138.31 list=SNMP
add address=143.55.37.40 list=SNMP
add address=143.55.37.41 list=SNMP
add address=132.147.132.24 list=SNMP
add address=198.100.49.99 list=SNMP
add address=132.147.132.26 list=SNMP
add address=132.147.132.40 list=SNMP
add address=204.11.183.126 list=SNMP
add address=173.215.67.124 list=SNMP
add address=132.147.138.3 list=SNMP
add address=132.147.138.7 list=SNMP
add address=132.147.138.21 list=SNMP
add address=132.147.138.26 list=SNMP
add address=142.147.112.3 list=WALLED-GARDEN
add address=142.147.112.19 list=WALLED-GARDEN
add address=107.178.15.27 list=WALLED-GARDEN
add address=142.147.112.12 list=WALLED-GARDEN
add address=132.147.147.56 list=WALLED-GARDEN
add address=35.227.221.107 list=WALLED-GARDEN
add address=172.66.155.116 list=WALLED-GARDEN
add address=104.20.19.83 list=WALLED-GARDEN
add address=132.147.175.10 list=managerIP
add address=132.147.175.14 list=managerIP

/ip firewall filter
add action=accept chain=input comment="ALLOW EST REL" connection-state=established,related,untracked
add action=accept chain=input comment="ALLOW MT NEIGHBOR" dst-port=5678 protocol=udp
add action=accept chain=input comment="ALLOW MAC TELNET" dst-port=20561 protocol=udp
add action=accept chain=input comment="ALLOW IGMP" protocol=igmp
add action=accept chain=input comment="ALLOW ICMP" protocol=icmp
add action=accept chain=input comment="ALLOW DHCPv4" dst-port=67 protocol=udp
add action=accept chain=input comment="ALLOW DHCPv6" dst-port=547 protocol=udp
add action=accept chain=input comment="ALLOW OSPF" protocol=ospf
add action=accept chain=input comment="ALLOW LDP" dst-port=646 protocol=tcp
add action=accept chain=input comment="ALLOW LDP" dst-port=646 protocol=udp
add action=accept chain=input comment="ALLOW MANAGER IP" src-address-list=managerIP
add action=accept chain=input comment="ALLOW BGP" dst-port=179 protocol=tcp src-address-list=BGP-ALLOW
add action=accept chain=input comment="ALLOW EOIP" protocol=gre src-address-list=EOIP-ALLOW
add action=accept chain=input comment="ALLOW SNMP" dst-port=161 protocol=tcp src-address-list=SNMP
add action=accept chain=input comment="ALLOW SNMP" dst-port=161 protocol=udp src-address-list=SNMP
add action=drop chain=input comment="DROP INPUT"
add action=accept chain=forward comment="NTP Allow" dst-address-list=NTP dst-port=123 in-interface=lan-bridge protocol=udp
add action=accept chain=forward comment="NTP Allow" dst-address=10.0.0.1 dst-port=123 in-interface=lan-bridge protocol=udp
add action=drop chain=forward comment="Traceroute Drop" out-interface=lan-bridge protocol=icmp src-address=10.0.0.0/8
add action=drop chain=forward comment="Private Space Protect" dst-address=10.0.0.0/8 in-interface=lan-bridge
add action=accept chain=forward comment="BGP Accept" dst-address=10.0.0.0/8 dst-port=179 protocol=tcp src-address=10.0.0.0/8
add action=accept chain=forward comment="GRE Accept " dst-address=10.0.0.0/8 protocol=gre src-address=10.0.0.0/8
add action=drop chain=forward comment="unauth drop rule" dst-address-list=!WALLED-GARDEN src-address-list=unauth
add action=fasttrack-connection chain=forward connection-state=established,related,untracked hw-offload=yes
add action=accept chain=forward connection-state=established,related,untracked

/ip firewall mangle
add action=jump chain=postrouting comment=TOS-MARKED dscp=!0 jump-target=TOS-MARKED
add action=jump chain=prerouting comment="NO CONN, NO PACK - Jump to CONN-MARK" connection-mark=no-mark jump-target=CONN-MARK packet-mark=no-mark
add action=jump chain=prerouting comment="CONN, NO PACK - Jump to PACK-MARK" connection-mark=!no-mark jump-target=PACK-MARK
add action=jump chain=forward comment="PACK mark - Jump to TOS-MARKING" jump-target=TOS-MARKING packet-mark=!no-mark
add action=mark-connection chain=CONN-MARK comment=NETFLIX dst-address-list=NETFLIX new-connection-mark=NETFLIX-CONN
add action=mark-connection chain=CONN-MARK comment=NETFLIX new-connection-mark=NETFLIX-CONN src-address-list=NETFLIX
add action=mark-connection chain=CONN-MARK comment="winbox / ssh / telnet - management-con - P2-CONN" dst-address-type=local dst-port=8291,5022,5023 new-connection-mark=P2-CONN protocol=tcp
add action=mark-connection chain=CONN-MARK comment=WOW dst-port=3724,1119,6881-6999 new-connection-mark=P2-CONN protocol=tcp
add action=mark-connection chain=CONN-MARK comment=WOW dst-port=3724,1119,6881-6999 new-connection-mark=P2-CONN protocol=udp
add action=mark-connection chain=CONN-MARK comment=XBOX dst-port=3074 new-connection-mark=P2-CONN protocol=tcp
add action=mark-connection chain=CONN-MARK comment=XBOX dst-port=3074 new-connection-mark=P2-CONN protocol=udp
add action=mark-connection chain=CONN-MARK comment="pings - P2-CONN" dst-address-type=local new-connection-mark=P2-CONN protocol=icmp
add action=mark-connection chain=CONN-MARK comment="voip - generic voip - P1-CONN" dst-port=5060,10000-30000 new-connection-mark=P1-CONN protocol=udp
add action=mark-connection chain=CONN-MARK comment="voip - dest voip-servers - P1-CONN" connection-mark=no-mark dst-address-list=Voip-Servers new-connection-mark=P1-CONN
add action=mark-connection chain=CONN-MARK comment="voip - source voip servers - P1-CONN" connection-mark=no-mark new-connection-mark=P1-CONN src-address-list=Voip-Servers
add action=mark-connection chain=CONN-MARK comment="everything else - P4-CONN" connection-mark=no-mark new-connection-mark=P4-CONN
add action=return chain=CONN-MARK
add action=mark-packet chain=PACK-MARK comment=NETFLIX-PACK connection-mark=NETFLIX-CONN new-packet-mark=NETFLIX-PACK passthrough=no
add action=mark-packet chain=PACK-MARK comment=P1-CONN-P1-PACK connection-mark=P1-CONN new-packet-mark=P1-PACK passthrough=no
add action=mark-packet chain=PACK-MARK comment=P2-CONN-P2-PACK connection-mark=P2-CONN new-packet-mark=P2-PACK passthrough=no
add action=mark-packet chain=PACK-MARK comment=P3-CONN-P3-PACK connection-mark=P3-CONN new-packet-mark=P3-PACK passthrough=no
add action=mark-packet chain=PACK-MARK comment=P4-CONN-P4-PACK connection-mark=P4-CONN new-packet-mark=P4-PACK passthrough=no
add action=change-dscp chain=TOS-MARKING comment="NETFLIX-PACK - TOS 2" new-dscp=2 packet-mark=NETFLIX-PACK passthrough=no
add action=change-dscp chain=TOS-MARKING comment="P1-PACK - TOS 46" new-dscp=46 packet-mark=P1-PACK passthrough=no
add action=change-dscp chain=TOS-MARKING comment="P2-PACK - TOS 36" new-dscp=36 packet-mark=P2-PACK passthrough=no
add action=change-dscp chain=TOS-MARKING comment="P3-PACK - TOS 16" new-dscp=16 packet-mark=P3-PACK passthrough=no
add action=change-dscp chain=TOS-MARKING comment="P4-PACK - TOS 1" new-dscp=1 packet-mark=P4-PACK passthrough=no
add action=return chain=TOS-MARKING

/routing filter rule
add chain=bgr-a-bgp-in-filter disabled=no rule="if (dst in 0.0.0.0/0 && dst-len == 0 && protocol bgp) { set bgp-local-pref 500; accept; }"
add chain=bgr-b-bgp-in-filter disabled=no rule="if (dst in 0.0.0.0/0 && dst-len == 0 && protocol bgp) { set bgp-local-pref 500; accept; }"
add chain=bgr-a-bgp-in-filter disabled=no rule="if (dst in 0.0.0.0/0 && dst-len == 32 && protocol bgp && bgp-communities includes 26077:86) { set blackhole yes; accept; }"
add chain=bgr-b-bgp-in-filter disabled=no rule="if (dst in 0.0.0.0/0 && dst-len == 32 && protocol bgp && bgp-communities includes 26077:86) { set blackhole yes; accept; }"

/ip firewall nat
add action=redirect chain=dstnat dst-address-type=local dst-port=5022 protocol=tcp to-ports=22
add action=dst-nat chain=dstnat comment="unauth proxy rule" dst-address-list=!WALLED-GARDEN dst-port=80 protocol=tcp src-address-list=unauth to-addresses=107.178.15.27 to-ports=3128

/ip firewall raw
add action=drop chain=prerouting comment="DROP BAD UDP" port=0 protocol=udp

/ip firewall service-port
set ftp disabled=yes
set tftp disabled=yes
set sip disabled=yes

/ip service
set www disabled=yes port=1234
set ftp disabled=yes port=5021
set telnet disabled=yes port=5023
set api disabled=yes
set api-ssl disabled=yes

/mpls interface
add disabled=no interface=all mpls-mtu=8900

/mpls ldp
add disabled=no lsr-id={{ROUTER_ID}} transport-addresses={{ROUTER_ID}}

/mpls ldp accept-filter
{{MPLS_ACCEPT_FILTERS}}

/mpls ldp advertise-filter
{{MPLS_ADVERTISE_FILTERS}}

/mpls ldp interface
{{UPLINK_LDP_LINES}}

/radius
add address=142.147.112.2 secret=Nl22021234 service=dhcp src-address={{ROUTER_ID}} timeout=5s
add address=142.147.112.18 secret=Nl22021234 service=dhcp src-address={{ROUTER_ID}} timeout=5s

/routing bgp connection
{{BGP_CONNECTION_LINES}}

/routing ospf interface-template
add area={{OSPF_AREA_NAME}} comment=loop0 cost=10 disabled=no interfaces=loop0 networks={{LOOPBACK_IP}}/32 passive priority=1
add area={{OSPF_AREA_NAME}} comment="CPE/Tower Gear" cost=10 disabled=no interfaces=lan-bridge networks={{CPE_NETWORK_BASE}}/{{CPE_PREFIX}} priority=1
{{OLT1_OSPF_LINE}}
{{OLT2_OSPF_LINE}}
{{UPLINK_OSPF_LINES}}

/snmp
set contact={{SNMP_CONTACT}} enabled=yes location="{{LOCATION}}" src-address={{ROUTER_ID}} trap-community=*1

/system clock
set time-zone-name=America/Chicago

/system identity
set name={{ROUTER_IDENTITY}}

/system logging
set 0 action=echo
add action=syslog topics=critical
add action=syslog topics=error
add action=syslog topics=warning
add action=disk topics=critical
add action=disk topics=error
add action=disk topics=warning
add topics=critical
add topics=error
add topics=warning

/system note
set note="COMPLIANCE SCRIPT LAST RUN ON {{GENERATED_AT}}" show-at-login=no

/system ntp client
set enabled=yes

/user
add name=root password={{USER_ROOT_PASSWORD}} group=full
add name=deployment password={{USER_DEPLOYMENT_PASSWORD}} group=full
add name=infra password={{USER_INFRA_PASSWORD}} group=full
add name=ido password={{USER_IDO_PASSWORD}} group=full
add name=sts password={{USER_STS_PASSWORD}} group=full
add name=eng password={{USER_ENG_PASSWORD}} group=full
add name=noc password={{USER_NOC_PASSWORD}} group=full
add name=comeng password={{USER_COMENG_PASSWORD}} group=full
add name=devops password={{USER_DEVOPS_PASSWORD}} group=full
add name=acq password={{USER_ACQ_PASSWORD}} group=full
set admin password={{USER_ADMIN_PASSWORD}} group=read

/system ntp client servers
add address=52.128.59.240
add address=52.128.59.241
add address=ntp-pool.nxlink.com

/system resource irq rps
set ether1 disabled=no

/system routerboard settings
set auto-upgrade=yes

/system scheduler
add interval=1d name=nightly on-event= "/system script run \"backup\"\r \n/system script run \"dhcp-count\"\r \n" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive start-date=2013-06-21 start-time=00:00:00

/system script
add dont-require-permissions=no name=dhcp-count owner=root policy= ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="# _List stats for IP -> Pool\r \n#\r \n# criticalthreshold = output pool display in red if pool used is above t his %\r \n# warnthreshold = output pool display in gold if pool used is above this _%\r \n\r \n:local criticalthreshold 85\r \n:local warnthreshold 70\r \n\r \n# Internal processing below...\r \n# ----------------------------------\r \n/ip pool {\r \n :local poolname\r \n :local pooladdresses\r \n :local poolused\r \n :local poolpercent\r \n :local minaddress\r \n :local maxaddress\r \n :local findindex\r \n :local tmpint\r \n :local maxindex\r \n :local line\r \n\r \n :put (\"IP Pool Statistics\")\r \n :put (\"------------------\")\r \n\r \n# Iterate through IP Pools\r \n :foreach p in=[find] do={\r \n\r \n :set poolname [get $p name]\r \n :set pooladdresses 0\r \n :set poolused 0\r \n :set line \"\"\r \n\r \n :set line (\" \" . $poolname)\r \n\r \n# Iterate through current pool's IP ranges\r \n :foreach r in=[:toarray [get $p range]] do={\r \n\r \n# Get min and max addresses\r \n :set findindex [:find [:tostr $r] \"-\"]\r \n :if ([:len $findindex] > 0) do={\r \n :set minaddress [:pick [:tostr $r] 0 $findindex]\r \n :set maxaddress [:pick [:tostr $r] ($findindex + 1) [:len [:tostr $r]]]\r \n } else={\r \n :set minaddress [:tostr $r]\r \n :set maxaddress [:tostr $r]\r \n }\r \n\r \n# Convert to array of octets (replace '.' with ',')\r \n :for x from=0 to=([:len [:tostr $minaddress]] - 1) do={\r \n :if ([:pick [:tostr $minaddress] $x ($x + 1)] = \".\") do ={\r \n :set minaddress ([:pick [:tostr $minaddress] 0 $x] . \" ,\" . \r \n [:pick [:tostr $minaddress] ($x + 1) [:len [:tostr $minaddress]]]) }\r \n }\r \n :for x from=0 to=([:len [:tostr $maxaddress]] - 1) do={\r \n :if ([:pick [:tostr $maxaddress] $x ($x + 1)] = \".\") do ={\r \n :set maxaddress ([:pick [:tostr $maxaddress] 0 $x] . \" ,\" . \r \n [:pick [:tostr $maxaddress] ($x + 1) [:len [:tostr $maxaddress]]]) }\r \n }\r \n\r \n# Calculate available addresses for current range\r \n :if ([:len [:toarray $minaddress]] = [:len [:toarray $maxaddress]]) do={\r \n :set maxindex ([:len [:toarray $minaddress]] - 1)\r \n :for x from=$maxindex to=0 step=-1 do={\r \n# Calculate 256^($maxindex - $x)\r \n :set tmpint 1\r \n :if (($maxindex - $x) > 0) do={\r \n :for y from=1 to=($maxindex - $x) do={ :set tmpint ( 256 * $tmpint) }\r \n }\r \n :set tmpint ($tmpint * ([:tonum [:pick [:toarray $maxaddress] $x]] - \r \n [:tonum [:pick [:toarray $minaddress] $x]]) )\r \n :set pooladdresses ($pooladdresses + $tmpint)\r \n# for x\r \n }\r \n\r \n# if len array $minaddress = $maxaddress\r \n }\r \n\r \n# Add current range to total pool's available addresses\r \n :set pooladdresses ($pooladdresses + 1)\r \n\r \n# foreach r\r \n }\r \n\r \n# Now, we have the available address for all ranges in this pool\r \n# Get the number of used addresses for this pool\r \n :set poolused [:len [used find pool=[:tostr $poolname]]]\r \n :set poolpercent (($poolused * 100) / $pooladdresses)\r \n\r \n# Output information\r \n :set line ([:tostr $line] . \" [\" . $poolused . \"/\" . $pooladdresses . \"]\")\r \n :set line ([:tostr $line] . \" \" . $poolpercent . \" % used\") \r \n\r \n# Set colored display for used thresholds\r \n :if ( [:tonum $poolpercent] > $criticalthreshold ) do={\r \n :log error (\"IP Pool \" . $poolname . \" is \" . $poolpercent . \"% full\")\r \n :put ([:terminal style varname] . $line)\r \n :local Subject ([/system identity get name] . \" DHCP pool $poolname is at $poolpercent % Full\")\r \n :local Body (\"$poolused of $pooladdresses used\")\r \n /tool e-mail send to=\"brad@team.nxlink.com\" subject=$Subject body=$Body from=\"DHCP-ALERT@nxlink.com\"\r \n } else={\r \n :if ( [:tonum $poolpercent] > $warnthreshold ) do={\r \n :log warning (\"IP Pool \" . $poolname . \" is \" . $poolpercent . \"% full\")\r \n :put ([:terminal style syntax-meta] . $line)\r \n :local Subject ([/system identity get name] . \" DHCP pool $poolname is at $poolpercent % Full\")\r \n :local Body (\"$poolused of $pooladdresses used\")\r \n /tool e-mail send to=\"brad@team.nxlink.com\" subject=$Subject body=$Body from=\"DHCP-ALERT@nxlink.com\"\r \n } else={\r \n :put ([:terminal style none] . $line)\r \n }\r \n }\r \n\r \n# foreach p\r \n }\r \n# /ip pool\r \n}"
add dont-require-permissions=no name=backups owner=root policy= ftp,reboot,read,write,policy,test,password,sniff,sensitive source="# automated backup 2 External ftp\r \n\r \n# ftp configuration\r \n:local ftphost \"backup.nxlink.com\"\r \n:local ftpuser \"mtbackups\"\r \n:local ftppassword \"Mt55054321\"\r \n:local ftppath \"mtbackups\"\r \n\r \n# months array\r \n:local months (\"jan\",\"feb\",\"mar\",\"apr\",\"may\",\"jun\",\"jul\", \"aug\",\"sep\",\"oct\",\"nov\",\"dec\");\r \n\r \n# get time\r \n:local ts [/system clock get time]\r \n:set ts ([:pick $ts 0 2].[:pick $ts 3 5].[:pick $ts 6 8])\r \n\r \n# get Date\r \n:local ds [/system clock get date]\r \n# convert name of month to number\r \n:local month [ :pick $ds 0 3 ];\r \n:local mm ([ :find $months $month -1 ] + 1);\r \n:if ($mm < 10) do={ :set mm (\"0\" . $mm); }\r \n# set $ds to format YYYY-MM-DD\r \n:set ds ([:pick $ds 7 11] . $mm . [:pick $ds 4 6])\r \n\r \n\r \n# file name for system backup - file name will be UMDB-servername-date-time.backup\r \n:local fname1 ([/system identity get name].\"-\".$ds.\"-\".$ts.\".backup\")\r \n# file name for config export - file name will be UMDB-servername-date-time.rsc\r \n:local fname2 ([/system identity get name].\"-\".$ds.\"-\".$ts.\".rsc\")\r \n\r \n# backup the data\r \n\r \n/system backup save name=$fname1\r \n:log info message=\"System backup finished (1/2).\";\r \n/export compact file=$fname2\r \n:log info message=\"Config export finished (2/2).\"\r \n\r \n\r \n# upload the system backup\r \n:log info message=\"Uploading system backup (1/2).\"\r \n/tool fetch address=\"$ftphost\" src-path=$fname1 user=\"$ftpuser\" mode=ftp password=\"$ftppassword\" dst-path=\"$ftppath/$fname1\" upload=yes\r \n# upload the config export\r \n:log info message=\"Uploading config export (2/2).\"\r \n/tool fetch address=\"$ftphost\" src-path=$fname2 user=\"$ftpuser\" mode=ftp password=\"$ftppassword\" dst-path=\"$ftppath/$fname2\" upload=yes\r \n\r \n# delay time to finish the upload - increase it if your backup file is big\r \n:delay 60s;\r \n# find file name start with UMDB- then remove\r \n:foreach i in=[/file find] do={ :if ([:typeof [:find [/file get $i name ] \"RTR-\"]]!=\"nil\") do={/file remove $i}; }\r \n:log info message=\"Configuration backup finished.\";\r \n"

/user aaa
set use-radius=yes
