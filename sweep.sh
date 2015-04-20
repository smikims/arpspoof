#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Error: you must specify an interface name"
	exit 1
fi

# get the CIDR notation
IN=$(ip a | grep "$1" | tail -n 1)
arrIN=(${IN//\// })
IP=${arrIN[1]}
BITS=${arrIN[2]}
ITER=$((2**$((32-$BITS))))

# start with a full netmask
MASK=$((2#11111111111111111111111111111111))
MASK=$((MASK - ITER + 1))

# convert from dotted quad to a single integer
arrIP=(${IP//./ })
IPNUM=$((arrIP[0] << 24 | arrIP[1] << 16 | arrIP[2] << 8 | arrIP[3] << 0))
IPNUM=$((IPNUM & MASK)) # apply the mask

for ((i=0; i < ITER; ++i)); do
	# this type of ping gets through more firewalls than ICMP
	CURIP=$((IPNUM + i))
	tcping -q -u 10000 $CURIP 6000
	STAT=$?

	# status codes: 0 means connection was opened, 1 means we got a RST (which
	# means there is someone there to talk to), and 2 means we timed out
	# (timeout is 10000 us aka 10 ms, which is plenty for a LAN)
	if [ $STAT -ne 2 ]; then
		# convert back to dotted quad
		IP0=$((CURIP >> 24))
		IP1=$(($((CURIP >> 16)) & 255))
		IP2=$(($((CURIP >> 8))  & 255))
		IP3=$((CURIP & 255))
		
		IPSTR=$IP0"."$IP1"."$IP2"."$IP3
		echo $IPSTR
		if [[ $2 != "-p" ]]; then
			./arp $IPSTR 2 -q &
		fi
	fi
done
