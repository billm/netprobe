FROM alpine:3.22
RUN apk add --no-cache openssh nginx openssl redis net-snmp tftp-hpa dnsmasq chrony python3 \
      samba openldap openldap-back-mdb busybox-extras
RUN ssh-keygen -A \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=lab.netprobe.test" \
      -keyout /etc/nginx/lab.key -out /etc/nginx/lab.crt \
 && mkdir -p /srv/tftp /srv/share /run/openldap /var/lib/openldap/netprobe \
 && echo "netprobe-lab telnet" > /etc/issue.net
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY snmpd.conf /etc/snmp/snmpd.conf
COPY chrony.conf /etc/chrony/chrony.conf
COPY smb.conf /etc/samba/smb.conf
COPY slapd.conf /etc/openldap/slapd-lab.conf
COPY base.ldif /etc/openldap/base.ldif
RUN slapadd -f /etc/openldap/slapd-lab.conf -l /etc/openldap/base.ldif
COPY fakes.py start.sh /usr/local/bin/
CMD ["/bin/sh", "/usr/local/bin/start.sh"]
