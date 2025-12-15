config edit 1

system set hostname USINES-B

net set addr 10.124.5.179/24 iface eno1
net add addr 10.124.5.180/24 iface eno1
net add addr 10.124.5.181/24 iface eno1

clock set sync mode ntp
ntp set server primary type unicast addr 2.2.2.3
ntp bind on iface eno1
clock enable server interlink

snmpd bind on iface eno1
snmpd set user seclab
snmpd set port 161
snmpd enable

syslog bind on iface eno1
syslog enable remote
syslog set remote protocol udp
syslog set remote addr 2.2.2.4 port 514

syslog enable forward
syslog set forward mode server

firewall enable
firewall allow ip 10.124.5.178 on iface eno1

transport enable slot 1
transport set slot 1 protocol tcp collect on 10.124.5.181:502
transport set slot 1 label "USINE-1-MODBUS-IHM" 

transport enable slot 2
transport set slot 2 protocol tcp collect on 10.124.5.180:502
transport set slot 2 label "USINE-1-MODBUS-AUTOMATE"

transport enable slot 3
transport set slot 3 protocol tcp collect on 10.124.5.181:443
transport set slot 3 label "USINE-1-HTTPS-IHM"

transport enable slot 4
transport set slot 4 protocol udp collect on <ip_console_SNMP>:161
transport set slot 4 label "USINE-1-SNMP-RMOB"