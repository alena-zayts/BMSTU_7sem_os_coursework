#!/bin/sh

sudo rmmod firewall_module
sudo lsmod | grep firewall_module
make clean


make
sudo insmod firewall_module.ko
sudo lsmod | grep firewall_module
sudo dmesg | grep FW


./firewall_interface.exe --help

./firewall_interface.exe --all
./firewall_interface.exe --in --add --dest_ip=127.0.0.8
./firewall_interface.exe --all
------------------------- ping 127.0.0.8
sudo dmesg | grep FW | tail -n 3
./firewall_interface.exe --in --del --dest_ip=127.0.0.8
 
 
./firewall_interface.exe --out --add --protocol=TCP
./firewall_interface.exe --in --add --protocol=TCP
./firewall_interface.exe --all
./firewall_interface.exe --out --del --protocol=TCP
./firewall_interface.exe --in --del --protocol=TCP
./firewall_interface.exe --all
 

 
 
./firewall_interface.exe --block_u
sudo dmesg | grep FW | tail -n 1
 
 
 
 
 
./firewall_interface.exe --out --add --protocol=UDP
./firewall_interface.exe --in --add --protocol=UDP
./firewall_interface.exe --all
 
 ./firewall_interface.exe --out --add --dest_port=631
 ./firewall_interface.exe --out --add --dest_port=0



./firewall_interface.exe --block_spoof
./firewall_interface.exe --block_u

./firewall_interface.exe --all
sudo dmesg | grep FW
./firewall_interface.exe --in --add --src_ip=0.1.1.2
./firewall_interface.exe --in --add --src_ip=0.1.1.2
./firewall_interface.exe --in --add --dest_ip=0.1.1.3
./firewall_interface.exe --out --add --dest_ip=0.1.1.4
./firewall_interface.exe --out --add --dest_ip=0.1.1.5
./firewall_interface.exe --out --add --src_ip=0.1.1.6
./firewall_interface.exe --out --add --dest_port=443
./firewall_interface.exe --all
sudo dmesg | grep FW


./firewall_interface.exe --block_spoof





: <<'END_COMMENT'
./firewall_interface.exe --out --add --dest_ip=0.1.1.2
ping 0.1.1.2

./firewall_interface.exe --out --add --protocol=TCP
echo -n "test" >/dev/tcp/1.2.3.4/12345

./firewall_interface.exe --out --add --dest_port=443
telnet google.com 443

./firewall_interface.exe --in --add --dest_port=53
telnet 127.0.0.53 53






nslookup localhost
Server:        127.0.0.53
Address:    127.0.0.53#53

Non-authoritative answer:
Name:    localhost.localdomain
Address: 127.0.0.1
Name:    localhost.localdomain
Address: ::1





ip address
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:1c:42:e9:89:7f brd ff:ff:ff:ff:ff:ff
    inet 10.211.55.3/24 brd 10.211.55.255 scope global dynamic noprefixroute enp0s5
       valid_lft 742sec preferred_lft 742sec
    inet6 fdb2:2c26:f4e4:0:f18d:1186:7fc5:127e/64 scope global temporary dynamic
       valid_lft 601949sec preferred_lft 83087sec
    inet6 fdb2:2c26:f4e4:0:c901:f041:e358:11b6/64 scope global dynamic mngtmpaddr noprefixroute
       valid_lft 2591999sec preferred_lft 604799sec
    inet6 fe80::38af:d697:b33d:c11a/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

inet 10.211.55.3/24



cat /etc/hosts
127.0.0.1    localhost
127.0.1.1    parallels-Parallels-Virtual-Platform

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
END_COMMENT

