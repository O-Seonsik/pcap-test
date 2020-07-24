#include <pcap.h>
#include <stdio.h>

struct ether_header{
    u_int8_t dest[6];
    u_int8_t src[6];
    u_int8_t type[2];
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


void print(int size, u_int8_t *text){
    for(int i = 0; i < size; i++) printf("%02x ", text[i]);
    printf("\n");
}

ether_header getEther(const u_char *packet){
    ether_header ether;
    for(int i = 0; i < 6; i++) ether.dest[i] = packet[i];
    for(int i = 0; i < 6; i++) ether.src[i] = packet[i+6];
    ether.type[0] = packet[12];
    ether.type[1] = packet[13];

    return ether;
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
        print(sizeof(ether.dest), ether.dest);
        printf("src mac : ");
        print(sizeof(ether.src), ether.src);
        printf("type : ");
        print(sizeof(ether.type), ether.type);
    }

    pcap_close(handle);
}
