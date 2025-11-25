transport set slot 1 protocol tcp collect on 192.168.1.20:443
transport enable slot 1
firewall allow ip 10.0.0.2 dst 192.168.1.20 port 443 on iface eno1 protocol tcp
