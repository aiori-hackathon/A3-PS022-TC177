#ifndef __DNS_PACKET_H
#define __DNS_PACKET_H

#include <linux/types.h>

/* DNS Header Format (RFC 1035, Section 4.1.1) */
struct dnshdr {
    __u16 id;
    __u8  flags1; /* QR (1 bit), Opcode (4 bits), AA (1 bit), TC (1 bit), RD (1 bit) */
    __u8  flags2; /* RA (1 bit), Z (3 bits), RCODE (4 bits) */
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

#define DNS_QR_MASK 0x80 /* Bit 7 of flags1: 0 = Query, 1 = Response */

#endif /* __DNS_PACKET_H */
