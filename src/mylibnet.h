#include <pcap.h>

struct ether_header{
    u_int8_t dest[6];
    u_int8_t src[6];
    u_int8_t type[2];
};

struct ip_header{
    u_int8_t version;
    u_int8_t length;
    u_int8_t protocol;
    u_int8_t src[4];
    u_int8_t dest[4];
    u_int16_t totalLen;
};

struct tcp_header{
    u_int16_t src;
    u_int16_t dest;
    u_int8_t length;
};

ether_header getEther(const u_char *packet){
    ether_header ether;
    for(int i = 0; i < 6; i++) ether.dest[i] = packet[i];
    for(int i = 0; i < 6; i++) ether.src[i] = packet[i+6];
    ether.type[0] = packet[12];
    ether.type[1] = packet[13];

    return ether;
}

ip_header getIp(const u_char *packet){
    ip_header ip;
    ip.version = (packet[14] & 0xf0) >> 4;
    ip.length = (packet[14] & 0x0f) * 4;
    ip.totalLen = (packet[16] << 8) | packet[17];
    int srcLoc = 14 + (ip.length) - 8;
    int destLoc = 14 + (ip.length) - 4;
    for(int i = 0; i < 4; i++) ip.src[i] = packet[srcLoc+i];
    for(int i = 0; i < 4; i++) ip.dest[i] = packet[destLoc+i];
    ip.protocol = packet[23];

    return ip;
}


tcp_header getTcp(const u_char *packet, int ipLen){
    tcp_header tcp;
    int srcLoc = 14 + ipLen;
    int destLoc = srcLoc + 2;
    tcp.src = packet[srcLoc] << 8 | packet[srcLoc+1];
    tcp.dest = packet[destLoc] << 8 | packet[destLoc+1];
    tcp.length = (packet[srcLoc + 12] >> 4) * 4;

    return tcp;
}
