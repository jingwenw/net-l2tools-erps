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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_BPF_H
#include <sys/types.h>
#include <net/bpf.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif

#include "dot1ag/NetIf.h"


NetIf::NetIf(const char *ifname, string name) :
txBuffer(), ifname_(ifname), rxBuffer(), Runnable(name + " - " + string(ifname)) {

    this->mutex_ = new mutex();
    this->cond_ = new condition_variable();
    this->rx = new RX(this);

    getSrcMac(this->localMac, ifname);
}

NetIf::~NetIf() {
    /* Note: mutex and cond_ have been taken care of by Runnable */

    if (this->rx != NULL) {
        delete this->rx;
    }
}

int NetIf::registerListener(uint16_t etherType, NetIfListener *listener) {
    this->netIfListener[etherType] = listener;
    cout << *this << " :: bufferPacket():: listener found for 0x" <<
            hex << setfill('0') << setw(4) << (uint32_t) etherType << endl;
    cout << dec;
    return EXIT_SUCCESS;
}

pcap_t * NetIf::setupPcap() {
    pcap_t *handle = NULL;
    char filter_src[1024];
    struct bpf_program filter; /* compiled BPF filter */
    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * Filter on CFM frames, i.e. ether[12:2] == 0x8902 for untagged
     * frames or ether[16:2] == 0x8902 for tagged frames. Destination
     * MAC address should be our MAC address.
     */
    sprintf(filter_src, "not ether src %02x:%02x:%02x:%02x:%02x:%02x and "
            "(ether[12:2] == 0x%x or "
            " (ether[12:2] == 0x%x and ether[16:2] == 0x%x))",
            this->localMac[0], localMac[1], localMac[2],
            localMac[3], localMac[4], localMac[5],
            ETYPE_CFM, ETYPE_8021Q, ETYPE_CFM);

    /* open pcap device for listening */
    handle = pcap_open_live(ifname_, BUFSIZ, 1, 200, errbuf);
    if (handle == NULL) {
        perror(errbuf);
        return (handle);
    }

    /* Compile and apply the filter */

    pcap_compile(handle, &filter, filter_src, 0, 0);
    pcap_setfilter(handle, &filter);

    cout << "Pcap filter: " << filter_src << endl;

    return handle;
}

void NetIf::task() {

    int n;
    struct cfmhdr *cfmhdr;
    thread *t_rx = NULL;
    Dot1ag *dot1ag = NULL;

    t_rx = this->rx->start();
    if (t_rx != NULL) {

        /* The main loop of this NetIf */
        int loop = 0;
        while (1) {
            cout << *this << " :: In loop: will wait ... " << endl;
            unique_lock<mutex> ul(*(this->mutex_));
            this->cond_->wait(ul);
            cout << *this << " ::   In loop: waked up " << loop << endl;
            for (int i = 0; i < this->rxBuffer.size(); i++) {
                dot1ag = this->rxBuffer.at(0);
                this->rxBuffer.pop_front();
                dot1ag->printPacket();
                delete dot1ag;
            }

            ul.unlock();
            loop++;
        }

        /* To join the rx thread */
        t_rx->join();
    }
}

int NetIf::bufferPacket(Dot1ag* packet) {

    uint16_t etype = packet->getEtherType();
    NetIfListener *listener = NULL;
    if (this->netIfListener.find(etype) == this->netIfListener.end()) {
        cout << *this << " :: bufferPacket():: no listener for 0x" <<
                hex << setfill('0') << setw(4) << (uint32_t) etype << endl;
        cout << dec;

        mutex_->lock();
        rxBuffer.push_back(packet);

        /* To unlock and notify others to the packet is ready */
        mutex_->unlock();
        cond_->notify_all();
    } else {
        listener = this->netIfListener[etype];
        listener->bufferPacket(packet);
    }

    return EXIT_SUCCESS;
}

/*
 * Note: BPF is prefered for eth raw packet sending
 */
#ifdef HAVE_NET_BPF_H

char bpf_ifs[NR_BPF_IFS][BPF_IFS_MAXLEN] = {
    "/dev/bpf",
    "/dev/bpf0",
    "/dev/bpf1",
    "/dev/bpf2",
    "/dev/bpf3",
    "/dev/bpf4"
};

int NetIf::getSrcMac(uint8_t *ea, const char *dev) {
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_dl *sdl;
    caddr_t addr;
    int i;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if (strncmp(ifa->ifa_name, dev, sizeof (dev)) != 0) {
            continue; /* not the interface we are looking for */
        }
        sdl = (struct sockaddr_dl *) ifa->ifa_addr;
        if (sdl->sdl_family != AF_LINK) {
            continue; /* skip if this not a data link address */
        }
        addr = LLADDR(sdl);
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            ea[i] = addr[i];
        }
        return 0;
    }
    freeifaddrs(ifaddr);
    /* interface not found, return -1 */
    return -1;
}

int NetIf::sendPacket(const char *ifname) {
    int size = this->packetSize;
    int bpf;
    struct ifreq ifc;
    int complete_header = 1;
    int i;

    if (geteuid() != 0) {
        fprintf(stderr, "Execution requires superuser privilege.\n");
        exit(EXIT_FAILURE);
    }

    /* minimum size of Ethernet frames is ETHER_MIN_LEN octets */
    if (size < ETHER_MIN_LEN) {
        size = ETHER_MIN_LEN;
    }

    /* try to open BPF interfaces until it success */
    for (i = 0; i < NR_BPF_IFS; i++) {
        if ((bpf = open(bpf_ifs[i], O_RDWR)) == -1) {
            continue;
        } else {
            break;
        }
    }
    if (bpf == -1) {
        /* failed to open a BPF interface */
        return 0;
    }

    /* bind BPF to the outgoing interface */
    strncpy(ifc.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(bpf, BIOCSETIF, &ifc) > 0) {
        perror("BIOCSETIF");
        exit(EXIT_FAILURE);
    }
    /* tell BPF that frames contain an Ethernet header */
    if (ioctl(bpf, BIOCSHDRCMPLT, &complete_header) < 0) {
        perror("BIOCSHDRCMPLT");
        exit(EXIT_FAILURE);
    }
    if (write(bpf, buf, size) < 0) {
        perror("/dev/bpf");
        exit(EXIT_FAILURE);
    }
    close(bpf);
    return 0;
}

#else

int NetIf::getSrcMac(uint8_t *ea, const char *dev) {
    int s;
    int i;
    struct ifreq req;

    if (geteuid() != 0) {
        fprintf(stderr, "Execution requires superuser privilege.\n");
        exit(EXIT_FAILURE);
    }

    if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("opening socket");
        exit(EXIT_FAILURE);
    }

    /* get interface index */
    memset(&req, 0, sizeof (req));
    strncpy(req.ifr_name, dev, sizeof (req.ifr_name));

    /* get MAC address of interface */
    if (ioctl(s, SIOCGIFHWADDR, &req)) {
        perror(dev);
        exit(EXIT_FAILURE);
    }
    close(s);
    for (i = 0; i < ETH_ALEN; i++) {
        ea[i] = req.ifr_hwaddr.sa_data[i];
    }
    return 0;

}

int NetIf::sendPacket(const char * ifname, uint8_t *data, uint32_t size) {
    int ifindex;
    int s;
    struct ifreq req;
    struct sockaddr_ll addr_out;


    if (geteuid() != 0) {
        fprintf(stderr, "Execution requires superuser privilege.\n");
        return (EXIT_FAILURE);
    }

    /* minimum size of Ethernet frames is ETHER_MIN_LEN octets */
    if (size < ETHER_MIN_LEN) {
        size = ETHER_MIN_LEN;
    }

    /* open raw Ethernet socket for sending */
    if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("opening socket");
        return (EXIT_FAILURE);
    }

    /* get interface index */
    memset(&req, 0, sizeof (req));
    strncpy(req.ifr_name, ifname, sizeof (req.ifr_name));
    if (ioctl(s, SIOCGIFINDEX, &req)) {
        perror(ifname);
        return (EXIT_FAILURE);
    }
    ifindex = req.ifr_ifindex;

    /* set socket address parameters */
    memset(&addr_out, 0, sizeof (addr_out));
    addr_out.sll_family = AF_PACKET;
    addr_out.sll_protocol = htons(ETH_P_ALL);
    addr_out.sll_halen = ETH_ALEN;
    addr_out.sll_ifindex = ifindex;
    addr_out.sll_pkttype = PACKET_OTHERHOST;

    if ((sendto(s, data, size, 0, (struct sockaddr *) &addr_out,
            sizeof (addr_out))) < 0) {
        perror("sendto");
        return (EXIT_FAILURE);
    }
    close(s);
    return EXIT_SUCCESS;
}

#endif  /* The end of #ifdef HAVE_NET_BPF_H */

ostream & operator<<(ostream& os, const NetIf &nif) {
    os << "[" + nif.name_ + "(tid: " << this_thread::get_id() << ")]:: rx size: " << nif.rxBuffer.size() << endl;
    return os;
}

void NetIf::RX::task() {
    int n;
    struct cfmhdr *cfmhdr;
    struct pcap_pkthdr *pcap_hdr; /* header returned by pcap */
    const u_char *data;

    fd_set fdset;
    int opts;

    pcap_t *pcapHandle = netIf->setupPcap();
    int pcap_fd = pcap_get_selectable_fd(pcapHandle);

    /* set pcap file descriptor to non-blocking */
    opts = fcntl(pcap_fd, F_GETFL);
    if (opts < 0) {
        perror("F_GETFL on pcap fd");
        exit(EXIT_FAILURE);
    }
    opts = (opts | O_NONBLOCK);
    if (fcntl(pcap_fd, F_SETFL, opts) < 0) {
        perror("F_SETFL on pcap fd");
        exit(EXIT_FAILURE);
    }


    Dot1ag *dot1ag = NULL;
    struct timeval tval;

    /* listen for CFM frames */
    while (1) {
        int n;
        const u_char *data;

        /*
         * Wait for Ether frames, and 
         * set timer to be used in select call
         */
        tval.tv_sec = 0;
        tval.tv_usec = WAKEUP;

        FD_ZERO(&fdset);
        FD_SET(pcap_fd, &fdset);
        n = select(pcap_fd + 1, &fdset, NULL, NULL, &tval);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            perror("select");
            exit(EXIT_FAILURE);
        }

        if (n == 0)
            continue; /* pcap_fd not ready */
        n = pcap_next_ex(pcapHandle, &pcap_hdr, &data);
        switch (n) {
            case -1:
                pcap_perror(pcapHandle, "pcap_next_ex");
                break;
            case 0:
                break;
            case 1:
                cfmhdr = CFMHDR(data);
                dot1ag = new Dot1ag((uint8_t *) data, uint32_t(pcap_hdr->caplen));
                //                dot1ag->printPacket();
                netIf->bufferPacket(dot1ag);

                break;
            default:
                pcap_perror(pcapHandle, "pcap_next_ex() unexpected value");
                break;
        }
    }

}

