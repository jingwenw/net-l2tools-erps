/*
 * @brief: ERPS CMF Process declaration
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _ERPS_ENGINE_H_
#define _ERPS_ENGINE_H_

#include <string>
#include <deque>
#include <map>
using namespace std;

#include <pcap.h>

#include "dot1ag/Dot1ag.h"
#include "dot1ag/NetIfListener.h"
#include "dot1ag/NetIf.h"
#include "dot1ag/Dot1agCcm.h"
#include "dot1ag/Dot1agRAps.h"
#include "dot1ag/Dot1agLbm.h"

/*
 * To-do: using SIGALARM for scheduling periodically sending CCM/LBM messages 
 * The global variables used for timer signal
 */
static uint32_t nextLBMtransID;
static int next_packet;
static int count; /* default is to send five LBMs */

class ErpsEngine : public NetIfListener {
private:

    /* Inner class used for sending CCMs and LBMs continually */
    class TaskCfm : public Runnable {
    public:

        TaskCfm(ErpsEngine *engine) : erpsEngine(engine), Runnable("Task Cfm") {
            this->mutex_ = new mutex();
        }

        ~TaskCfm() {
            /* Note: mutex and cond_ have been taken care of by Runnable */
        }

        virtual void task();

        void setInterval(int interval) {
            CCMinterval = interval;
        };

        void setSkips(int skips) {
            CCMSkips = skips;
        };
    private:
        ErpsEngine *erpsEngine;
        int CCMinterval;
        int CCMSkips;
    };


    TaskCfm *taskCfm;

    NetIf *netIf0_;
    NetIf *netIf1_;

    /* The internal configuration data structure */
    struct NetIfCfg {
        const Dot1agAttr *dot1agAttr;
        Dot1agCcm *dot1agCcm;
        Dot1agRAps *dot1agRAps;
        Dot1agLbm *dot1agLbm;
        /* mac database, and updated by tracking CCMs received. */
        struct rMEP rMEPdb[MAX_MEPID + 1];

        NetIfCfg() {
            dot1agAttr = NULL;
            dot1agCcm = NULL;
            dot1agRAps = NULL;
            dot1agLbm = NULL;
        }
    };

    NetIfCfg netIf0Cfg_;

    int configNetIf(NetIfCfg *cfg, const Dot1agAttr *attr);

    void sendDot1agPacket(Dot1ag *dot1ag, uint32_t seq);

    void printRMEPState(const struct rMEP *rMEPdb, int rMEPid, const char *state) const {
        cout << endl << endl;
        cout << " rMEPid: " << rMEPid << " and mac: 0x" << hex << setfill('0') << setw(2) <<
                (unsigned int) rMEPdb[rMEPid].recvdMacAddress[0] << ":" <<
                (unsigned int) rMEPdb[rMEPid].recvdMacAddress[1] << ":" <<
                (unsigned int) rMEPdb[rMEPid].recvdMacAddress[2] << ":" <<
                (unsigned int) rMEPdb[rMEPid].recvdMacAddress[3] << ":" <<
                (unsigned int) rMEPdb[rMEPid].recvdMacAddress[4] << ":" <<
                (unsigned int) rMEPdb[rMEPid].recvdMacAddress[5] << " is " << state <<
                endl << endl;
        ;
    }

    int checkRMEPdb(NetIfCfg &cfg) {
        struct timeval now;
        int status = EXIT_SUCCESS;
        gettimeofday(&now, NULL);
        /* has one of the remote MEP timers run out? */
        for (int i = 1; i <= MAX_MEPID; i++) {
            if (cfg.rMEPdb[i].active == 0) {
                continue;
            }
            /* send log entry on UP to DOWN transition */
            if (cfm_timevalcmp(cfg.rMEPdb[i].rMEPwhile, now, <) &&
                    (cfg.rMEPdb[i].rMEPCCMdefect == 0)) {
                this->printRMEPState(cfg.rMEPdb, i, "DOWN");
                cfg.rMEPdb[i].rMEPCCMdefect = 1;
                status = EXIT_FAILURE;
            }
        }
        return status;
    }

    /*
     * To-do: using SIGALARM for scheduling periodically sending CCM/LBM messages 
     */
    void scheduleTimer();

    static void timeout_handler(int sig) {
        next_packet = 1;
        count--;
        nextLBMtransID++;
        cout << endl << "Timeout: thread_id: " << this_thread::get_id() << endl;
    };

    friend ostream& operator<<(ostream& os, const ErpsEngine& ee);

public:

    ErpsEngine(NetIf *netIf0, const Dot1agAttr *attr, string name = "ERPS Engine");

    virtual ~ErpsEngine();

    /*
     * Will start 2 thread: the engine itself in task(), and TaskCfm::task() 
     */
    void startService();


protected:
    /* 
     * This task is to handle received CFM packets and react accordingly 
     */
    void task();

    /*
     * Handling CCMs received
     */
    int processCcm(NetIfCfg &cfg, const uint8_t *data, int verbose = 1);


};


#endif /* The end of #ifndef _ERPS_ENGINE_H_ */

