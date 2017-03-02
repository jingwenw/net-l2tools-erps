/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <time.h>

#include <sys/ioctl.h>

#ifdef HAVE_NET_BPF_H
#include <sys/types.h>
#include <net/bpf.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif



#include <pcap.h>


#include "dot1ag/Dot1ag.h"

Dot1agLtm::Dot1agLtm(int vlan, uint8_t *srcmac, uint8_t *dstmac): buf{0},
            currentPos (buf), packetSize(sizeof(struct ether_header)) {
        int i;
        struct ether_header *p = (struct ether_header *) buf;

        /* set destination MAC address */
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
                p->ether_dhost[i] = dstmac[i];
        }

        /* set source MAC address */
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
                p->ether_shost[i] = srcmac[i];
        }

        
}



/*
 *  Linktrace Message Format
 *                                  octet
 *  +---------------------------+
 *  | Common CFM Header         |   1-4
 *  +---------------------------+
 *  | LTM Transaction Identifier|   5-8
 *  +---------------------------+
 *  | LTM TTL                   |    9
 *  +---------------------------+
 *  | Original MAC Address      |  10-15
 *  +---------------------------+
 *  | Target MAC Address        |  16-21
 *  +---------------------------+
 *  | Additional LTM TLVs       |
 *  +---------------------------+
 *  | END TLV (0)               |
 *  +---------------------------+
 */

void Dot1agLtm::cfm_addltm(uint32_t transID, uint8_t ttl, uint8_t *orig_mac,
                uint8_t *target_mac) {

        struct cfm_ltm *p;
        int i;

        p = POS_CFM_LTM(buf);
        p->transID = htonl(transID);
        p->ttl = ttl;
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
                p->orig_mac[i] = orig_mac[i];
                p->target_mac[i] = target_mac[i];
        }
}


void Dot1agLtm::cfm_ltm_setttl(uint8_t ttl) {
        struct cfm_ltm *p;

        p = POS_CFM_LTM(buf);
        p->ttl = ttl;
}

void Dot1agLtm::cfm_ltm_settransid(uint32_t trans_id) {
        struct cfm_ltm *p;

        p = POS_CFM_LTM(buf);
        p->transID = htonl(trans_id);
}


void Dot1agLtm::cfm_addltr(uint32_t transID, uint8_t ttl, uint8_t action) {
        struct cfm_ltr *p;

        p = POS_CFM_LTR(buf);
        p->transID = htonl(transID);
        p->ttl = ttl;
        p->action = action;
}


/*
 * Return 1 if the frame in buf matches the expected LTR, return 0 otherwise
 */
int Dot1agLtm::cfm_matchltr(uint8_t *dst, uint16_t vlan, uint8_t md_level,
                         uint32_t trans_id, int *hit_target) {
        struct cfmencap *encap;
        struct cfmhdr *cfmhdr;
        struct cfm_ltr *ltr;
        int i;

        encap = (struct cfmencap *) buf;

        /* Check ethertype */
        if (IS_TAGGED(buf)) {
                if (encap->ethertype != htons(ETYPE_CFM)) {
                        return (0);
                }
        } else {
                if (encap->tpid != htons(ETYPE_CFM)) {
                        return (0);
                }
        }

        for (i = 0; i < ETHER_ADDR_LEN; i++) {
                if (encap->dstmac[i] != dst[i]) {
                        return 0;
                }
        }
        cfmhdr = CFMHDR(buf);
        /* check if this is an LTR frame */
        if (cfmhdr->opcode != CFM_LTR) {
                return 0;
        }
        ltr = (struct cfm_ltr *) POS_CFM_LTR(buf);
        /* check for correct nextTransID */
        if (ntohl(ltr->transID) != trans_id) {
                return 0;
        }

        if (ltr->action == ACTION_RLYHIT) {
                *hit_target = 1;
        }
        return 1;
}

