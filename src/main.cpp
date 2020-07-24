#include <pcap.h>
#include <stdio.h>
#include "mylibnet.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print(int size, u_int8_t *text, bool isHex){
    if(isHex)
        for(int i = 0; i < size; i++) printf("%02x ", text[i]);
    else
        for(int i = 0; i < size; i++) printf(i == size -1? "%d" : "%d.", text[i]);
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        ether_header ether = getEther(packet);

        // Ethernet Header type isn't 0x0800 then Pass the packet
        if(!(ether.type[0] == 0x08 && ether.type[1] == 0x00)) continue;

        printf("Ethernet : \n");
        printf("dest mac : ");
        print(sizeof(ether.dest), ether.dest, 1);
        printf("src mac : ");
        print(sizeof(ether.src), ether.src, 1);
        printf("type : ");
        print(sizeof(ether.type), ether.type, 1);

        printf("IP : \n");
        printf("src ip : ");
        ip_header ip = getIp(packet);
        print(sizeof(ip.src), ip.src, 0);
        printf("dest ip ; ");
        print(sizeof(ip.dest), ip.dest, 0);


    }

    pcap_close(handle);
}
