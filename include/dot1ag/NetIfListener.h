/*
 * @brief: CFM Net Interface which does tx/rx
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _NET_IF_LISTENER_H_
#define _NET_IF_LISTENER_H_

#include <string>
#include <deque>
using namespace std;

#include <pcap.h>

#include "ieee8021ag.h"
#include "Dot1ag.h"
#include "Runnable.h"

class NetIfListener : public Runnable {
public:

    NetIfListener(string name = "NetIf Listener");

    virtual ~NetIfListener();

    int bufferPacket(Dot1ag *packet);

protected:

    deque<Dot1ag *> txBuffer;
    deque<Dot1ag *> rxBuffer;


private:

    friend ostream& operator<<(ostream& os, const NetIfListener& nif);
};



#endif /* The end of #ifndef _NET_IF_LISTENER_H_ */

