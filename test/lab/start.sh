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
exec python3 /usr/local/bin/fakes.py
