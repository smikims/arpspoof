#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#define DIE(format, error)                              \
	do {                                    \
		fprintf(stderr, format, error); \
		exit(EXIT_FAILURE);             \
	} while (0)


int main(void)
{
	/* get an ARP socket */
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (fd == -1) {
		DIE("%s\n", strerror(errno));
	}

	/* this is the name of my ethernet interface */
	const char *if_name = "enp4s0";
	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		DIE("%s\n", "interface name is too long");
	}

	/* this gets the number of the network interface */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	int ifindex = ifr.ifr_ifindex;

	/* will be sent to everyone */
	const unsigned char ether_broadcast_addr[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* special socket address type used for AF_PACKET */
	struct sockaddr_ll addr = {0};
	addr.sll_family   = AF_PACKET;
	addr.sll_ifindex  = ifindex;
	addr.sll_halen    = ETHER_ADDR_LEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

	/* construct the ARP request */
	struct ether_arp req;
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = ETHER_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op  = htons(ARPOP_REQUEST);
	/* zero because that's what we're asking for */
	memset(&req.arp_tha, 0, sizeof(req.arp_tha));

	/* dummy address for now, this doesn't even make sense */
	const char *target_ip_string = "127.0.0.1";
	struct in_addr target_ip_addr = {0};
	if (!inet_aton(target_ip_string, &target_ip_addr)) {
		DIE("%s is not a valid IP address\n", target_ip_string);
	}
	memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));

	/* now to get the our hardware address */
	if (ioctl(fd,SIOCGIFHWADDR,&ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		DIE("%s\n", "not an ethernet interface");
	}
	memcpy(&req.arp_sha, (unsigned char *) ifr.ifr_hwaddr.sa_data, sizeof(req.arp_sha));

	/* ...and our network address */
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	memcpy(&req.arp_spa, (unsigned char *) ifr.ifr_addr.sa_data, sizeof(req.arp_spa));

	/* actually send it */
	if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		DIE("%s\n", strerror(errno));
	}

	return 0;
}
