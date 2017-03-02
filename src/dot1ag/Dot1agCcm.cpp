/*
 * @brief: Dot1ag CMF CCM PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    Author: James Wang
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#include "dot1ag/net_common.h"

#include "dot1ag/Dot1agCcm.h"

Dot1agCcm::Dot1agCcm(const Dot1agAttr *attr) : Dot1ag(attr) {
    
    uint8_t flags = 0;
    int CCMinterval = 4; /* default to 1 sec */

   setDstMac(ETHER_CFM_GROUP); // set CFM multicat mac as destination
           
    /* The last bype of the dstmac is 3y, y = md_level */
    this->etherHeader_p->ether_dhost[5] = 0x30 + (attr->md_level & 0x0F);

    /* least-significant three bits are the CCM Interval */
    switch (attr->CCMinterval) {
        case 10:
            /* 10 ms */
            CCMinterval = 2;
            break;
        case 100:
            /* 100 ms */
            CCMinterval = 3;
            break;
        case 1000:
            /* 1 sec */
            CCMinterval = 4;
            break;
        case 10000:
            /* 10 sec */
            CCMinterval = 5;
            break;
        case 60000:
            /* 1 min */
            CCMinterval = 6;
            break;
        case 600000:
            /* 10 min */
            CCMinterval = 7;
            break;
        default:
            /* 1 sec */
            CCMinterval = 4;
            break;
    }
    flags |= (CCMinterval & 0x07);

    /* add CFM common header to packet */
    addCfmHdr(attr->md_level, flags, FIRST_TLV_CCM, CFM_CCM, DOT1AG_VERSION_0);

    addCcm(attr->md_level, attr->md, attr->ma, attr->mepid, 0);

    /* add Sender ID TLV */
    addTLV(TLV_SENDER_ID, 0);

    /* add Port Status TLV */
    addTLV(TLV_PORT_STATUS, DOT1AG_PS_UP);

    /* add Interface Status TLV */
    addTLV(TLV_INTERFACE_STATUS, DOT1AG_IS_UP);

    /* end packet with End TLV field */
    addTLV(TLV_END, 0);
    
}

void Dot1agCcm::addCcm(uint8_t md_level, const char *md, const char *ma, uint16_t mepid,
        uint32_t CCIsentCCMs) {

    int i;
    struct cfm_cc *cfm_cc;
    uint8_t *p;
    int mdnl;
    int smanl;
    int max_smanl;

    cfm_cc = (struct cfm_cc *) (buf + this->packetSize);

    /* add 4 octet Sequence Number to packet */
    cfm_cc->seqNumber = htonl(CCIsentCCMs);
    CCIsentCCMs++;
    cfm_cc->mepid = htons(mepid);
    
    /*
     * To-do: Always assume character string format for now, 
     * use character string (4) as Maintenance Domain Name Format
     */
    cfm_cc->maid.format = 4;
    cfm_cc->maid.length = strlen(md);
    if (cfm_cc->maid.length > DOT1AG_MAX_MD_LENGTH) {
        cfm_cc->maid.length = DOT1AG_MAX_MD_LENGTH;
    }
    
    /* set p to start of variable part in MAID */
    p = cfm_cc->maid.var_p;
    /* fill variable part of MAID with 0 */
    memset(p, 0, sizeof (cfm_cc->maid.var_p));
    
    /* copy Maintenance Domain Name to MAID */
    mdnl = strlen(md);
    if (mdnl > DOT1AG_MAX_MD_LENGTH) {
        mdnl = DOT1AG_MAX_MD_LENGTH;
    }
    memcpy(p, md, mdnl);
    p += mdnl;
    /* set Short MA Name Format to character string (2) */
    *p = 2;
    p++;
    
    /* set Short MA Name Length */
    max_smanl = sizeof (struct cfm_maid) - 4 - mdnl;
    smanl = strlen(ma);
    if (smanl > max_smanl) {
        smanl = max_smanl;
    }
    *p = smanl;
    p++;
    
    /* copy Short MA Name to MAID */
    memcpy(p, ma, smanl);
    /* field defined by ITU-T Y.1731, transmit as 0 */
    memset(cfm_cc->y1731, 0, sizeof (cfm_cc->y1731));

    this->packetSize += sizeof (struct cfm_cc);

}

int Dot1agCcm::cfmMatchCcm(const uint8_t *data) const {
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

    cfmhdr = CFMHDR(data);
    if (cfmhdr->opcode != CFM_CCM) {
        return (0);
    }
    cout << "  CFM opcode matched..." << endl;

    return (1);
}

