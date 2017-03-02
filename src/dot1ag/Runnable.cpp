/*
 * @brief: Thread Interface definition
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
#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
using namespace std;

#include "dot1ag/Runnable.h"

Runnable::Runnable(string name) : name_(name) {
}

Runnable::~Runnable() {
    if (mutex_ != NULL) {
        delete mutex_;
    }
    if (cond_ != NULL) {
        delete cond_;
    }
    if (thread_ != NULL) {
        delete thread_;
    }
}

int Runnable::init() {
    this->state_ = INIT;
}

thread *Runnable::start() {
    cout << endl << *this << " :: To start ..." << endl;    
    this->thread_ = new thread([ = ]{task();});
    this->state_ = STARTED;
    cout << *this << " :: started" << endl << endl;
    return this->thread_;
}

int Runnable::stop() {
    this->state_ = STOPPED;
}

ostream & operator<<(ostream& os, const Runnable & r) {
    os << "[" + r.name_ + "(tid: " << this_thread::get_id() << ")]:: " << endl;
    return os;
}