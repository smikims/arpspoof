arpspoof
========

A program to perform an ARP spoofing attack against someone else on your local unencrypted network.

The arpspoof.c file sends 2 ARP requests, one to the default gateway and one to the victim, to get their MAC addresses. I then use these addresses to construct a phony ARP response to the victim that tells them that I am their default gateway (or any other IP address if you don't want it to be the default gateway). Some operating systems (e.g. Linux) are very suspicious of spurious ARP responses like this and will quickly figure out the ruse, but Windows will happily chug along in blissful ignorance until you annoy it by taking too long to respond to requests. To prevent even this weak defense mechanism from deploying, the program has an option to keep resending the phony packet every X number of seconds. Note: if it takes more than about 1 second to print the second line your response probably got lost, so try again.

##Syntax

./arpspoof [OPTION [ARG]]... VICTIM_IP

##Options

-i, --interface		Network interface to use, given as the argument. If this
                    option is not used, the interface defaults to the first
					running non-loopback interface.

-r, --repeat		Resends the packet continuously with a delay given in
                    seconds by the argument. A delay of zero means only one
					packet is sent.

-s, --spoof-ip		Spoof to an IP (given as an argument) other than the default
                    gateway.

-v, --verbose		Prints out extra info about the machines' MAC addresses.

#sweep.sh

The sweep.sh file gets the current IP address and routing prefix in CIDR
notation and from this calculates the netmask, then uses this information to
ping sweep everyone on the current subnet and attempt to send phony ARP packets
to them using the arp.c program. Obviously you shouldn't do this unless you know
exactly who will be affected by it and you're prepared to handle the
consequences. There is also a flag to do only the ping sweep and not attempt the
spoofing, which prints out the IP addresses of everyone who responded in some
fashion to the ping from the tcping program (not mine) on port 6000. For some
reason I was unable to determine, Windows responds to random TCP connections on
port 6000 but firewalls almost everything else, including ICMP. Go figure.

##Syntax

./sweep.sh INTERFACE_NAME [ -p (ping only) ]

#cage.sh

cage.sh is a simple URL rewriter script for Squid--it just takes any URL and
turns it into a picture of Nicolas Cage.

#Miscellaneous

There are also some other relevant things, for example the sample website is
available under the http directory, and the Apache and Squid configuration files
are here as well. And one more thing that doesn't really fit neatly anywhere
else: the iptables rule to redirect the traffic. By default Linux just forwards
any IP packets destined for elsewhere, so the ARP spoof by itself won't really
affect anything other than making the victim's packets pass through your
machine. However, since it's *your* machine, you can have your way with them, so
we set up iptables to redirect anything coming through port 80 to port 3129 on
our machine, which Apache is listening on as well as Squid (just make sure
you've set them up not to conflict if you're running both). Note that HTTPS
(port 443) is significantly harder to mess with, so I don't try.

iptables rule (run as root):

iptables -t nat -A PREROUTING -p tcp --dport 80 -i $INTERFACE_NAME -j DNAT \
--to $DEST_IP:$DEST_PORT

Things you change yourself are prefixed with $'s this time to distinguish from
literal ALLCAPS arguments.

#Notes

This project was originally written for my networking class last semester, but
since a few other people seem to be interested in it I've been cleaning it up a
bit recently and adding a few more features. My main focus is in the main
arpspoof program; the functionality of sweep.sh will probably be incorporated
into it and the rest of the stuff in this repo, which is basically just a really
simple proof of concept, may eventually be removed.

