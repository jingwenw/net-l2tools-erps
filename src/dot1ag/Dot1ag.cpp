/*
 * @brief: Dot1ag CMF PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    Author: James Wang
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#include "dot1ag/net_common.h"

#include <sys/ioctl.h>


#include <pcap.h>

#include "dot1ag/Dot1ag.h"

#include "dot1ag/NetIf.h"

Dot1ag::Dot1ag() : buf{0}, attr(), packetSize(0), dstMacString("") {
}

Dot1ag::Dot1ag(const uint8_t * data, uint32_t len) : buf{0}
, packetSize(0), dstMacString("") {
    memcpy(buf, data, len);
    this->packetSize = len;
}

Dot1ag::Dot1ag(const Dot1agAttr * attr) : attr(attr) {
    struct ether_header *p = (struct ether_header *) buf;

    /* set destination MAC address */
    if (attr->remoteMac == NULL) {
        memcpy(p->ether_dhost, attr->dstMac, ETHER_ADDR_LEN);
    } else {
        setDstMac(attr->remoteMac);
    }

    /* set source MAC address */
    if (attr->ifname == NULL) {
        memcpy (p->ether_shost, attr->srcMac, ETHER_ADDR_LEN);
    } else {
        NetIf::getSrcMac(etherHeader_p->ether_shost, attr->ifname);
    }

    setVlanAndSize(attr->vlan);
}

/* Parse a MAC address */
int Dot1ag::eth_addr_parse(uint8_t *addr, const char *str) {
    unsigned int cval;
    char c, orig, sep;
    int pos;

    cval = 0;
    sep = 0;
    pos = 0;

    memset(addr, 0, ETHER_ADDR_LEN);

    do {
        c = orig = *str++;

        if (c == 0) {
            if (!sep) return (-1);
            c = sep;
        }

        switch (c) {
            case '0' ... '9':
                cval = (cval << 4) + (c - '0');
                break;
            case 'a' ... 'f':
                cval = (cval << 4) + (c - 'a' + 10);
                break;
            case 'A' ... 'F':
                cval = (cval << 4) + (c - 'A' + 10);
                break;

            case ':':
            case '-':
                if (!sep) {
                    sep = c;
                } else {
                    if (sep != c)
                        return (-1);
                }

                if ((pos > 5) || (cval > 0xFF))
                    return (-1);

                addr[pos] = cval;
                pos++;
                cval = 0;
                break;

            case '.':
                if (!sep) {
                    sep = '.';
                } else {
                    if (sep != '.')
                        return (-1);
                }

                if ((pos > 2) || (cval > 0xFFFF))
                    return (-1);

                addr[pos << 1] = cval >> 8;
                addr[(pos << 1) + 1] = cval & 0xFF;
                pos++;
                cval = 0;
                break;

            default:
                return (-1);
        }
    } while (orig != 0);

    if (((sep == ':') || (sep == '-')) && (pos != 6))
        return (-1);

    if ((sep == '.') && (pos != 3))
        return (-1);

    return (0);
}

/* print an Etherner address in colon separated hex, no newline */
void Dot1ag::eaprint(uint8_t *ea) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
            ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);
}

void Dot1ag::printPacket() {
    cout << endl;
    cout << "  Packets with " << packetSize << " bytes: " << endl;
    for (int i = 0; i < this->packetSize; i++) {
        if (i % 16 == 0) {
            cout << endl;
            cout << "  0x" << hex << setfill('0') << setw(2) << i << " : ";
        }
        cout << hex << setfill('0') << setw(2) << (unsigned int) buf[i];
        if ((i % 16 != 15) && (i != (this->packetSize - 1))) {
            cout << ":";
        }
    }
    cout << dec << endl;
}

/*
 *      fields in the Tag Control Information (TCI)
 *
 *       8   6 5 4     1 8             1
 *      +-----+-+-------+---------------+
 *      |     |C|       |               |
 *      | PCP |F|<-------- VID -------->|
 *      |     |I|       |               |
 *      +-----+-+-------+---------------+
 */

void Dot1ag::tci_setpcp(uint8_t pcp, uint16_t *tci) {
    /* clear PCP bits */
    *tci &= 0x1fff;
    /* set new PCP value */
    *tci |= (pcp << 13);
}

void Dot1ag::tci_setcfi(uint8_t cfi, uint16_t *tci) {
    if (!((cfi == 0) || (cfi == 1))) {
        fprintf(stderr, "tci_setcfi: CFI must be 0 or 1\n");
        cfi = 1;
    }
    /* set CFI bit */
    *tci |= (cfi << 8);
}

void Dot1ag::tci_setvid(uint16_t vid, uint16_t *tci) {
    if ((vid <= 0) || (vid >= 0xfff)) {
        fprintf(stderr, "tci_setvid: allowed VID range is 1-4094\n");
        vid = 1;
    }
    /* set VID */
    *tci = vid & 0xfff;
}

/*
 *  Common CFM Header
 *                       octet
 * +------------------+
 * | MD Level         |  1 (high-order 3 bits)
 * +------------------+
 * | Version          |  1 (low-order 5 bits)
 * +------------------+
 * | Opcode           |  2
 * +------------------+
 * | Flags            |  3
 * +------------------+
 * | First TLV Offset |  4
 * +------------------+
 *
 */

void Dot1ag::addCfmHdr(uint8_t md_level, uint8_t flags, uint8_t first_tlv,
        uint8_t opcode, uint8_t version) {

    struct cfmhdr *p = CFMHDR(buf);

    /* MD level must be in range 0-7 */
    if (md_level > 7) {
        fprintf(stderr, "cfm_addhdr: allowed MD level range is 0-7\n");
        md_level = 0;
    }
    /* set whole octet to 0, version is set to 0 too */
    p->octet1.version = version;
    /* MD Level is the high order 3 bits */
    p->octet1.md_level |= (md_level << 5) & 0xe0;
    p->opcode = opcode;
    p->flags = flags;
    p->tlv_offset = first_tlv;

    // do not forget to add the cfm header to packetSize
    this->packetSize += sizeof (struct cfmhdr);
}

void Dot1ag::setVlanAndSize(uint16_t vlan) {
    struct ether_header *p = (struct ether_header *) buf;
    this->packetSize = sizeof (struct ether_header);
    if (vlan > 0) {
        /* set ethertype to 802.1Q tagging */
        p->ether_type = htons(ETYPE_8021Q);

        /*
         * next 16 bits consist of:
         * +--------+-------+---------+
         * | 3 bits | 1 bit | 12 bits |
         * +--------+-------+---------+
         *     PCP     CFI      VID
         */

        /* set PCP and CFI to zero */
        *((uint16_t *) (buf + this->packetSize)) = htons(vlan & 0xfff);
        this->packetSize += 2;

        /* set Ethernet type to CFM (0x8902) */
        *((uint16_t *) (buf + this->packetSize)) = htons(ETYPE_CFM);
        this->packetSize += 2;
    } else {
        p->ether_type = htons(ETYPE_CFM);
    }

}

int Dot1ag::addTLV(uint8_t type, uint16_t len, const uint8_t *value) {
    uint8_t *p = NULL;

    /* Type */
    *(uint8_t *) (buf + this->packetSize) = type;
    this->packetSize += sizeof (uint8_t);

    if (type > TLV_END) {
        /* minimal length of 1 */
        *(uint16_t *) (buf + this->packetSize) = htons(len);
        this->packetSize += sizeof (uint16_t);

        /* Values */
        p = buf + this->packetSize;
        memcpy(p, value, len);
        this->packetSize += len;
    }
    return this->packetSize;
}

int Dot1ag::addTLV(uint8_t type, uint8_t value) {
    return addTLV(type, 1, &value);
}

const string * Dot1ag::getDstMacString() {
    stringstream ss;

    if (this->dstMacString.empty()) {
        /* Create the dstMac string, for debug purpose */
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            ss << hex << setfill('0') << setw(2) << (unsigned int) remotemac[i];
            if (i < 5) {
                ss << ":";
            }
            this->dstMacString = ss.str();
        }
    }
    return &(this->dstMacString);
}