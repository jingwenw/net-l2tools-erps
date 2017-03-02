/*
 * @brief: Dot1ag CMF R-APS PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    Author: James Wang
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#include "dot1ag/net_common.h";

#include "dot1ag/Dot1agRAps.h"
#include "dot1ag/NetIf.h"

Dot1agRAps::Dot1agRAps(const Dot1agAttr *attr) : Dot1ag(attr) {

    /* Set the destination to the R-APS multicast address */
    rApsDstMac[5] = attr->ring_id;
    setDstMac(rApsDstMac);
    
    /* add CFM common header to packet */
    addCfmHdr(attr->md_level, 0, FIRST_TLV_RAPS, CFM_RAPS, DOT1AG_VERSION_1);

    addRAps(ERP_PKTIO_PDU_REQUEST_SIGNAL_FAIL, etherHeader_p->ether_shost);

    /* end packet with End TLV field */
    addTLV(TLV_END, 0);    
}

void Dot1agRAps::addRAps(uint8_t request, uint8_t *nid) {

    struct raps_pdu *p;
    int i;

    /* Move pointer to the start of R-APS pdu position */
    p = (struct raps_pdu *) POS_CFM_PDU(buf);

    p->subcode = request;

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        p->nodeID[i] = nid[i];
    }

    packetSize += sizeof (struct raps_pdu);
}

int Dot1agRAps::cfmMatchRAps(const uint8_t *data) const {
    struct cfmencap *cfmencap;
    struct cfmhdr *cfmhdr;
    int i;
    uint8_t *dst = etherHeader_p->ether_dhost;
    uint8_t *src = etherHeader_p->ether_shost;

    cfmencap = (struct cfmencap *) data;

    /* Check ethertype */
    if (IS_TAGGED(data)) {
        if (cfmencap->ethertype != htons(ETYPE_CFM)) {
            return (0);
        }
    } else {
        if (cfmencap->tpid != htons(ETYPE_CFM)) {
            return (0);
        }
    }
    cout << "  CFM EtherType matched..." << endl;
    
    /*
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (cfmencap->dstmac[i] != src[i]) {
            return (0);
        }
        if (cfmencap->srcmac[i] != dst[i]) {
            return (0);
        }
    }
    cout << "  Eth Mac addresss matched..." << endl;
     */
    
    cfmhdr = CFMHDR(data);
    if (cfmhdr->opcode != CFM_RAPS) {
        return (0);
    }
    cout << "  CFM opcode matched..." << endl;

    return (1);
}

uint8_t Dot1agRAps::rApsDstMac[ETHER_ADDR_LEN] = {0x01, 0x19, 0xA7, 0x00, 0x00, 0x01};

