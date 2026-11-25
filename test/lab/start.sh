#!/bin/sh
# Starts every lab service; the container exits if any of them dies.
set -eu
/usr/sbin/sshd
nginx
redis-server --protected-mode no --daemonize yes
snmpd -Lo -C -c /etc/snmp/snmpd.conf
in.tftpd -l -s /srv/tftp
dnsmasq --no-resolv --no-hosts
chronyd -x -f /etc/chrony/chrony.conf
smbd -D
slapd -f /etc/openldap/slapd-lab.conf -h ldap:///
busybox-extras telnetd -p 23 -l /bin/login
exec python3 /usr/local/bin/fakes.py
