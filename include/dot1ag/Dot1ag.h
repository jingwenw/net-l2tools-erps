/*
 * @brief: CFM PDU Encapsulation with type/length media
 * 
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 * 
 * Created on March 7, 2017
 *
 */

#ifndef _DOT1AG_H_
#define _DOT1AG_H_

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <pcap.h>

#include "ieee8021ag.h"

/*
 * Additionals to ieee8021ag.h, due to support of R-APS
 */

#define DOT1AG_VERSION_1        1


/* Point to the position of the PDU - right behind of the headers */
#define POS_CFM_PDU(s)          (void *) \
                                (CFMHDR_U8((s),sizeof(struct cfmhdr)))

#define POS_CFM_TID(s)          (struct cfm_tid *) \
                                (CFMHDR_U8((s),sizeof(struct cfmhdr)))

#define ETHER_TYPE(s)           (uint16_t *) \
                                (IS_TAGGED(s) ? \
                                        ((s) + ETHER_ADDR_LEN * 2 + \
                                        ETHER_DOT1Q_LEN) : \
                                        ((s) + 12))

#define FIRST_TLV_RAPS 32

struct raps_pdu {
    uint8_t request : 4;
    uint8_t subcode : 4;
    uint8_t status_rb : 1;
    uint8_t status_dnf : 1;
    uint8_t status_bpr : 1;
    uint8_t satus_reserved : 5;
    uint8_t nodeID[6];
    uint8_t reserved[24];
} __attribute__((__packed__));

#define ERP_PKTIO_PDU_REQUEST_FORCED_SWITCH        0b1101    /* forced switch */
#define ERP_PKTIO_PDU_REQUEST_EVENT                0b1110    /* event */
#define ERP_PKTIO_PDU_REQUEST_SIGNAL_FAIL          0b1011    /* signal fail */
#define ERP_PKTIO_PDU_REQUEST_MANUAL_SWITCH        0b0111    /* manual switch */
#define ERP_PKTIO_PDU_REQUEST_NO_REQUEST           0b0000    /* No request */

/*
 * Dot1ag attributes data structure, mainly used to create different Dot1ag
 * messages 
 */
struct Dot1agAttr {
    uint32_t transId; /* Transaction Id or Sequence Number */
    uint16_t mepid; /* MA End Point Identifier */
    uint16_t vlan;
    uint8_t md_level;
    uint8_t ring_id;
    int CCMSkips;

    uint32_t CCMinterval;
    const uint8_t srcMac[ETHER_HDR_LEN];
    const uint8_t dstMac[ETHER_HDR_LEN];
    const char *md;
    const char *ma;
    const char *ifname;
    const char *remoteMac;
    int verbose; // debug purpose

    Dot1agAttr() : srcMac({0}), dstMac({0}) {
        transId = 0;
        mepid = -1;
        vlan = 0;
        md_level = 0;
        ring_id = 2;
        CCMSkips = 0;
        CCMinterval = 1000;
        md = "HCL";
        ma = "HCL_ERPS";
        ifname = NULL;
        remoteMac = NULL;
        verbose = 0;
    }
} __attribute__((__packed__));

class Dot1ag {
public:
    static const uint16_t BUFFER_MAX_SIZE = 1516;

    Dot1ag();
    Dot1ag(const uint8_t * data, uint32_t len);
    Dot1ag(const Dot1agAttr * attr);

    virtual ~Dot1ag() {
    };

    /* Parse a MAC address */
    static int eth_addr_parse(uint8_t *addr, const char *str);

    /* print an Etherner address in colon separated hex, no newline */
    static void eaprint(uint8_t *ea);

    void printPacket();

    void
    tci_setpcp(uint8_t pcp, uint16_t *tci);

    void
    tci_setcfi(uint8_t cfi, uint16_t *tci);

    void
    tci_setvid(uint16_t vid, uint16_t *tci);

    void
    addCfmHdr(uint8_t md_level, uint8_t flags, uint8_t first_tlv,
            uint8_t opcode, uint8_t version);

    void setVlanAndSize(uint16_t vlan);
    int addTLV(uint8_t type, uint16_t len, const uint8_t *value);
    int addTLV(uint8_t type, uint8_t value);

    void setTransId(uint32_t trans_id) {
        struct cfm_tid *p;
        p = POS_CFM_TID(buf);
        p->transID = htonl(trans_id);
    }

    int setDstMac(const char *mac) {
        return Dot1ag::eth_addr_parse(this->etherHeader_p->ether_dhost, mac);
    }

    int setDstMac(const uint8_t *mac) {
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            this->etherHeader_p->ether_dhost[i] = mac[i];
        }
        return 0;
    }
    
    uint16_t getEtherType() const {
        return ntohs(*(ETHER_TYPE(this->buf)));
    };

    uint32_t getTransId() const {
        struct cfm_tid *p;
        p = POS_CFM_TID(buf);
        return ntohl(p->transID);
    };

    uint32_t getPacketSize() const {
        return this->packetSize;
    };

    uint8_t *getPacketData() {
        return this->buf;
    };
    const string *getDstMacString();

protected:
    uint8_t buf[BUFFER_MAX_SIZE];

    struct ether_header *etherHeader_p = (struct ether_header *) buf;
    uint8_t *localmac = etherHeader_p->ether_shost;
    uint8_t *remotemac = etherHeader_p->ether_dhost;
    uint32_t packetSize;
    
    const Dot1agAttr *attr;

private:
    string dstMacString;
};

#endif /* The end of #ifndef _DOT1AG_H_ */

