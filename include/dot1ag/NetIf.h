/*
 * @brief: CFM Net Interface which does tx/rx
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _NET_IF_H_
#define _NET_IF_H_

#include <string>
#include <deque>
#include <map>
using namespace std;

#include <pcap.h>

#include "ieee8021ag.h"
#include "Dot1ag.h"
#include "Runnable.h"
#include "NetIfListener.h"

class NetIf : public Runnable {
public:
    static const uint32_t WAKEUP = 20000;

    NetIf(const char *ifname, string name = "NetIf");

    virtual ~NetIf();

    pcap_t * setupPcap();

    /* Anyone want to receive the ether packet need to call this func to register */
    int registerListener(uint16_t etherType, NetIfListener *listener);

    const char *getIfName() {
        return this->ifname_;
    };
    
    int sendPacket(Dot1ag *packet) {
        return NetIf::sendPacket(this->ifname_, packet->getPacketData(),
                packet->getPacketSize());
    }
    
    const uint8_t *getLocalMac() const { return this->localMac; } 
    
    /* For sending raw ether packet over the given dev in ifname */
    static int sendPacket(const char * ifname, uint8_t *data, uint32_t size);
    static int getSrcMac(uint8_t *ea, const char *dev);
    
    static void updateTimeFromNow(struct timeval &tval, uint32_t sec, uint32_t usec) {
        struct timeval now;
        gettimeofday(&now, NULL);
        tval.tv_sec = now.tv_sec + sec;
        tval.tv_usec += now.tv_usec + usec;
        if (tval.tv_usec >= 1000000) {
            tval.tv_sec++;
            tval.tv_usec %= 1000000;
        }
    }

protected:

    /* Inner class used for receiving ether packets */
    class RX : public Runnable {
    public:

        RX(NetIf *netIf) : Runnable("RX"), netIf(netIf) {
            this->mutex_ = netIf->mutex_;
            this->cond_ = netIf->cond_;
        }
        virtual void task();
    private:
        NetIf *netIf;
    };

    /* the main thread task */
    virtual void task();

    /* add packets into the buffer, thread safe */
    int bufferPacket(Dot1ag *packet);



private:
    const char *ifname_;
    deque<Dot1ag *> txBuffer;
    deque<Dot1ag *> rxBuffer;
    map<uint16_t, NetIfListener *> netIfListener;

    uint8_t localMac[ETHER_ADDR_LEN];

    RX *rx;

    friend ostream& operator<<(ostream& os, const NetIf& nif);
};



#endif /* The end of #ifndef _NET_IF_H_ */

