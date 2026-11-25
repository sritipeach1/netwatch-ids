#!/bin/bash
# Intentionally weak services for a closed lab network. Never expose this container.
/usr/sbin/sshd
dnsmasq --no-daemon --no-resolv --address=/#/10.0.1.10 &
exec nginx -g 'daemon off;'
