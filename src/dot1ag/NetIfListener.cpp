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

#include "dot1ag/NetIfListener.h"

NetIfListener::NetIfListener(string name) : txBuffer(), rxBuffer(), Runnable(name) {
    this->mutex_ = new mutex();
    this->cond_ = new condition_variable();
}

NetIfListener::~NetIfListener() {
    /* Note: mutex and cond_ have been taken care of by Runnable */
}

int NetIfListener::bufferPacket(Dot1ag* packet) {
    mutex_->lock();

    this->rxBuffer.push_back(packet);

    /* To unlock and notify others to the packet is ready */
    mutex_->unlock();
    cond_->notify_all();
    
    return EXIT_SUCCESS;
}

ostream & operator<<(ostream& os, const NetIfListener &nifl) {
    os << nifl.name_ +  " rx size: " << nifl.rxBuffer.size() << endl;
    return os;
}

