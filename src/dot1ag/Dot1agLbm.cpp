/*
 * @brief: Dot1ag CMF_LBM PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    Author: James Wang
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#include <iostream>
using namespace std;

#include "dot1ag/Dot1agLbm.h"

Dot1agLbm::Dot1agLbm(const Dot1agAttr *attr) : Dot1ag(attr) {
    uint32_t nextLBMtransID;

    /* add CFM common header to packet */
    addCfmHdr(attr->md_level, 0, FIRST_TLV_LBM, CFM_LBM, DOT1AG_VERSION_0);

    /*
     *  add 4 octet Loopback Transaction Identifier to packet
     * seed random generator
     */
    srandom(time(0));
    /* initialize transaction ID with random value */
    nextLBMtransID = random();
    
    setTransId(nextLBMtransID);
    packetSize += sizeof (uint32_t);

    /*
     *  finally add Sender ID TLV
     */
    addTLV(TLV_SENDER_ID, 0); // Chassis ID Length is 0 (no Chassis ID present)

    /* end packet with End TLV field */
    addTLV(TLV_END, 0);

}


/*
 * Return 1 if the frame in buf matches the expected LBR, return 0 otherwise
 */
int Dot1agLbm::cfm_matchlbr(const uint8_t *data) {
    struct cfmencap *cfmencap;
    struct cfmhdr *cfmhdr;
    int i;
    uint8_t *dst = etherHeader_p->ether_dhost;
    uint8_t *src = etherHeader_p->ether_shost;

    cfmencap = (struct cfmencap *) data;

    /* Check ethertype */
    if (IS_TAGGED(data)) {
        if (cfmencap->ethertype != htons(ETYPE_CFM)) {
            return (EXIT_FAILURE);
        }
    } else {
        if (cfmencap->tpid != htons(ETYPE_CFM)) {
            return (EXIT_FAILURE);
        }
    }
    cout << "  CFM EtherType mached..." << endl;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (cfmencap->dstmac[i] != src[i]) {
            return (EXIT_FAILURE);
        }
        if (cfmencap->srcmac[i] != dst[i]) {
            return (EXIT_FAILURE);
        }
    }
    cout << "  Ether Mac addresss matched..." << endl;
    cfmhdr = CFMHDR(data);
    if (cfmhdr->opcode != CFM_LBR) {
        return (EXIT_FAILURE);
    }
    cout << "  CFM opcode matched..." << endl;
    
        struct cfm_tid *p;

    p = POS_CFM_TID(data);
    
    if (ntohl(p->transID) != this->getTransId()) {
        cout << "  TID mismatched: mine is " << this->getTransId() << " while received: " << ntohl(p->transID) << endl;
        return (EXIT_FAILURE);
    }
    cout << "  CFM TID matched." << endl;
    return (EXIT_SUCCESS);
}

int Dot1agLbm::convertDotagLbm2Lbr(Dot1ag *lb, const uint8_t *localMac) {
        uint8_t *lb_frame = lb->getPacketData();
        
	struct cfmhdr *cfmhdr;
	struct ether_header *lbr_ehdr;
	int i;

	lbr_ehdr = (struct ether_header *) lb_frame;

	/* check for valid source mac address */
	if (ETHER_IS_MCAST(lbr_ehdr->ether_shost)) {
		fprintf(stderr, "LBR received from multicast address\n");
		return EXIT_FAILURE;
	}

	/*
	 * Destination mac address should be either our MAC address or the
	 * CCM group address.
	 */
	if (!(ETHER_IS_CCM_GROUP(lbr_ehdr->ether_dhost) ||
		ETHER_IS_EQUAL(lbr_ehdr->ether_dhost, localMac))) {
		/* silently drop LBM */
		return EXIT_FAILURE;
	}

	/* set proper src and dst mac addresses */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		lbr_ehdr->ether_dhost[i] = lbr_ehdr->ether_shost[i];
		lbr_ehdr->ether_shost[i] = localMac[i];
	}

	cfmhdr = CFMHDR(lb_frame);
	cfmhdr->opcode = CFM_LBR;

	return EXIT_SUCCESS;
}
