/*
 * @brief: Thread Interface
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _RUNNABLE_H_
#define _RUNNABLE_H_

#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
using namespace std;

class Runnable {
public:

    enum state { INIT, STARTED, STOPPED };

    Runnable(string name = "Runnable");
    
    virtual ~Runnable();

    int init();
    thread *start();
    int stop();
    
    virtual void task() = 0;
           
protected:
    
    string name_;
    thread *thread_;
    mutex *mutex_;
    condition_variable *cond_;
    enum state state_;

    friend ostream& operator<<(ostream& os, const Runnable& r);
    
};

#endif /* The end of #ifndef _RUNNABLE_H_ */

