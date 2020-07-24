#include <pcap.h>

#ifndef MYLIBNET_H
#define MYLIBNET_H
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
    int srcLoc = 14 + (ip.length) - 8;
    int destLoc = 14 + (ip.length) - 4;
    for(int i = 0; i < 4; i++) ip.src[i] = packet[srcLoc+i];
    for(int i = 0; i < 4; i++) ip.dest[i] = packet[destLoc+i];

    return ip;
}


tcp_header getTcp(const u_char *packet, int ipLen){
    tcp_header tcp;
    int srcLoc = 14 + ipLen;
    int destLoc = srcLoc + 2;

    tcp.src = (u_int16_t(packet[srcLoc]) << 4) & u_int16_t(packet[srcLoc+1]);
    tcp.dest = (u_int16_t(packet[destLoc]) << 4) & u_int16_t(packet[destLoc+1]);
    printf("%d\n", tcp.src);
    printf("%d\n", tcp.dest);

    tcp.length = packet[srcLoc + 13];
    printf("%d\n", tcp.length);
    return tcp;
}
#endif // MYLIBNET_H

