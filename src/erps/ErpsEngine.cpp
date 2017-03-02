/*
 * @brief: ERPS main functions, receiving/sending and reacting to CFM CCMs
 *         and R-APSs.
 * 
 * To-do: 
 *      - There is only one NetIf used for this engine, while for a real ERPS
 *        topology, there should be 2 net interfaces involved.
 *      - For better performance and accuracy, SIGNALARM signal might be preferred
 *        for periodic CCM/LBM sending.
 *
 *    Copyright (c) 2017
 *    Author: James Wang
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#include "dot1ag/net_common.h"

#include <signal.h>

#include "erps/ErpsEngine.h"
#include "dot1ag/ieee8021ag.h"
#include "dot1ag/NetIf.h"

ErpsEngine::ErpsEngine(NetIf *netIf0, const Dot1agAttr *attr, string name) : netIf1_(NULL),
netIf0_(netIf0), NetIfListener(name) {

    this->mutex_ = new mutex();
    this->cond_ = new condition_variable();
    this->taskCfm = new TaskCfm(this);

    configNetIf(&this->netIf0Cfg_, attr);
    /* Listener to the packet received from the NetIf */
    netIf0->registerListener(ETYPE_CFM, this);

    /* initialize remote MEP database */
    for (int i = 1; i <= MAX_MEPID; i++) {
        this->netIf0Cfg_.rMEPdb[i].active = 0;
    }
}

ErpsEngine::~ErpsEngine() {
    /* Note: mutex and cond_ have been taken care of by Runnable */

    if (netIf0Cfg_.dot1agCcm != NULL) {
        delete netIf0Cfg_.dot1agCcm;
    }
    if (netIf0Cfg_.dot1agRAps != NULL) {
        delete netIf0Cfg_.dot1agRAps;
    }
    if (netIf0Cfg_.dot1agLbm != NULL) {
        delete netIf0Cfg_.dot1agLbm;
    }

    if (taskCfm != NULL) {
        delete taskCfm;
    }
}

/*
 * Will start 2 thread: the engine itself in task(), and TaskCfm::task() 
 */
void ErpsEngine::startService() {
    thread *thread_engine = this->start();

    /* wait a second to start taskCfm after the main ErpsEngine starts */
    sleep(1);

    thread *thread_cfm = this->taskCfm->start();
    thread_cfm->join();
    thread_engine->join();
}

int ErpsEngine::configNetIf(NetIfCfg *netIfCfg, const Dot1agAttr *attr) {
    // Save the dot1ag attr to the NetIf config.
    netIfCfg->dot1agAttr = attr;

    /* MD level should be in range 0-7 */
    if (attr->md_level > 7) {
        fprintf(stderr, "MD level should be in range 0-7\n");
        exit(EXIT_FAILURE);
    }

    this->taskCfm->setInterval(attr->CCMinterval);
    this->taskCfm->setSkips(attr->CCMSkips);

    /* check for mandatory '-m' flag */
    if ((attr->mepid > 0) && (attr->mepid < 8192)) {

        netIfCfg->dot1agCcm = new Dot1agCcm(attr);

        int seq = netIfCfg->dot1agCcm->getTransId();
        cout << "Sending CFM CCM start tid: " << seq <<
                " with size: " << netIfCfg->dot1agCcm->getPacketSize() << endl;

    }

    if (attr->remoteMac != NULL) {
        netIfCfg->dot1agLbm = new Dot1agLbm(attr);
    }
    /* build R-APS packets */
    netIfCfg->dot1agRAps = new Dot1agRAps(attr);

    return EXIT_SUCCESS;
}

int ErpsEngine::processCcm(NetIfCfg &cfg, const uint8_t *data, int verbose) {

    struct cfmencap *encap;
    struct cfmhdr *cfmhdr;
    struct cfm_cc *cfm_cc;
    uint8_t mdnl = 0;
    int i;
    uint8_t *md_namep;
    uint8_t sma_name_fmt;
    uint8_t smanl = 0;
    uint8_t local_mac[ETHER_ADDR_LEN];
    struct timeval now;
    int rMEPid;
    int more_tlvs;
    int tlv_length;
    uint8_t *p;
    const Dot1agAttr *attr = cfg.dot1agAttr;
    struct rMEP *rMEPdb = cfg.rMEPdb;

    encap = (struct cfmencap *) data;

    /* discard if not received on our vlan */
    if ((GET_VLAN(encap) != attr->vlan) && (IS_TAGGED((uint8_t*) encap))) {
        fprintf(stderr, "Vlan not match: CCM received with vlan %d "
                "(ours %d)\n", GET_VLAN(encap), attr->vlan);
        return (EXIT_FAILURE);
    }
    if ((attr->vlan != 0) && (!IS_TAGGED((uint8_t*) encap))) {
        return (EXIT_FAILURE);
    }

    /* We need to parse the CCM header first in order to get the MEP ID */
    cfm_cc = POS_CFM_CC(data);
    /* discard if CCM has the same MEPID as us */
    if (cfm_cc->mepid == htons(attr->mepid)) {
        fprintf(stderr,
                "config error: CCM received with our MEPID %d "
                "(ours %d)\n",
                ntohs(cfm_cc->mepid), attr->mepid);
        return (EXIT_FAILURE);
    } else {
        rMEPid = ntohs(cfm_cc->mepid);
    }

    /* parse the generic CFM header */
    cfmhdr = CFMHDR(data);

    if (verbose) {
        fprintf(stderr, "rcvd CCM from: "
                "%02x:%02x:%02x:%02x:%02x:%02x, level %d",
                encap->srcmac[0], encap->srcmac[1],
                encap->srcmac[2], encap->srcmac[3],
                encap->srcmac[4], encap->srcmac[5],
                GET_MD_LEVEL(cfmhdr));
    }

    /* discard if MD Level is different from ours */
    if (GET_MD_LEVEL(cfmhdr) != attr->md_level) {
        rMEPdb[rMEPid].CCMreceivedEqual = 0;
        if (verbose) {
            fprintf(stderr,
                    " (expected level %d, discard frame)\n",
                    attr->md_level);
        }
        return (EXIT_FAILURE);
    } else {
        rMEPdb[rMEPid].active = 1;
        rMEPdb[rMEPid].CCMreceivedEqual = 1;
        this->printRMEPState(rMEPdb, rMEPid, "ACTIVE");
    }

    /* extract the Maintenance Domain Name, if present */
    md_namep = cfm_cc->maid.var_p;

    /* create a '\0' filled buffer for MD Name */
    char mdnamebuf[DOT1AG_MAX_MD_LENGTH + 1];
    memset(mdnamebuf, '\0', sizeof (mdnamebuf));

    switch (cfm_cc->maid.format) {
        case 0:
            /* reservered for IEEE 802.1 */
            break;
        case 1:
            /* No Maintenance Domain Name present */
            break;
        case 2:
            /* Domain Name based string */
            break;
        case 3:
            /* MAC address + 2-octet integer */
            break;
        case 4:
            /* Character string */
            mdnl = cfm_cc->maid.length;
            if ((mdnl < 1) || (mdnl > DOT1AG_MAX_MD_LENGTH)) {
                fprintf(stderr, "illegal MD Name Length: %d\n", mdnl);
                break;
            }
            /* copy MD Name to buffer, ensuring trailing '\0' */
            strncpy(mdnamebuf, (char *) md_namep, mdnl);

            if (verbose) {
                fprintf(stderr, ", MD \"%s\"", mdnamebuf);
            }
            /* discard if MD Name is different from ours */
            if (strncmp(mdnamebuf, attr->md,
                    strlen(attr->md) > mdnl ? strlen(attr->md) : mdnl)
                    != 0) {
                if (verbose) {
                    fprintf(stderr,
                            " (expected \"%s\", discard frame)\n",
                            attr->md);
                }
                return (EXIT_FAILURE);
            }
            break;
        default:
            /*
             *  5-31:   Reserved for IEEE 802.1
             *  32-63:  Defined by ITU-T Y.1731
             *  64-255: Reserved for IEEE 802.1
             */
            break;
    }

    /*
     * MAID field size is 48 octets
     * MD Name Format: 1 octet
     * MD Name Length: 1 octet
     * Short MA Name Format: 1 octet
     * Short MA Name Length: 1 octet
     * MD Name + Short MA Name <= 48 - 4
     * Zero padding at the end
     */

    /* extract the Short MA Name */
    /* Short MA Name Format starts after MD Name */
    sma_name_fmt = *(md_namep + mdnl);

    /* create a '\0' filled buffer, ensuring trailing '\0' */
    /* maximum SMA length is "MAID_SIZE - mdnl - 4" */
    char smanamebuf[MAID_SIZE - mdnl - 4 + 1];
    memset(smanamebuf, '\0', sizeof (smanamebuf));

    switch (sma_name_fmt) {
        case 0:
            /* Reserved for 802.1 */
            break;
        case 1:
            /* Primary VID */
            break;
        case 2:
            /* Character String */
            smanl = *(md_namep + mdnl + sizeof (sma_name_fmt));
            if (smanl < 1) {
                fprintf(stderr, "illegal Short MA Length: %d\n",
                        smanl);
                break;
            }
            if (smanl + mdnl > MAID_SIZE - 4) {
                smanl = MAID_SIZE - mdnl - 4;
            }

            /* copy Short MA Name to buffer */
            strncpy(smanamebuf, (char *) (md_namep + mdnl + 2), smanl);

            if (verbose) {
                fprintf(stderr, ", MA \"%s\"", smanamebuf);
            }

            /* discard if MA name is different from ours */
            if (strncmp(smanamebuf, attr->ma,
                    strlen(attr->ma) > smanl ? strlen(attr->ma) : smanl)
                    != 0) {
                if (verbose) {
                    fprintf(stderr,
                            " (expected \"%s\", discard frame)\n",
                            attr->ma);
                }
                return (EXIT_FAILURE);
            }
            break;
        case 3:
            /* 2-octet Integer */
            break;
        case 4:
            /* RFC2685 VPN ID */
            break;
        default:
            /*
             *  5-31:   Reserved for IEEE 802.1
             *  32-63:  Defined by ITU-T Y.1731
             *  64-255: Reserved for IEEE 802.1
             */
            break;
    }
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        rMEPdb[rMEPid].recvdMacAddress[i] = encap->srcmac[i];
    }

    /* start parsing TLVs */
    p = POS_CFM_CC_TLVS(data);
    more_tlvs = 1; /* there are more TLVs to parse */
    while (more_tlvs) {
        tlv_length = ntohs(*(uint16_t *) (p + 1));
        switch (*p) {
            case TLV_END:
                /* End TLV */
                more_tlvs = 0; /* last TLV, stop further parsing */
                break;
            case TLV_SENDER_ID:
                /* Sender ID TLV */
                /* XXX not implemented yet */
                break;
            case TLV_ORG_SPECIFIC:
                /* Organization-Specific TLV */
                /* XXX not implemented yet */
                break;
            case TLV_PORT_STATUS:
                /* Port Status TLV */
                rMEPdb[rMEPid].tlv_ps = *(p + 3);
                break;
            case TLV_INTERFACE_STATUS:
                /* Interface Status TLV */
                rMEPdb[rMEPid].tlv_is = *(p + 3);
                break;
            default:
                break;
        }
        /* skip over TLV length + value fields to next TLV */
        p += sizeof (uint16_t) + tlv_length + 1;
    }

    if (verbose) {
        fprintf(stderr, "\n");
    }

    /* send log entry on DOWN to UP transition */
    if (rMEPdb[rMEPid].rMEPCCMdefect == 1) {
        rMEPdb[rMEPid].rMEPCCMdefect = 0;
        this->printRMEPState(rMEPdb, rMEPid, "UP");
    }

    /*
     * Set rMEPwhile to 3.5x CCMinterval. rMEPwhile is the
     * timeout after which it is assumed that the remote
     * MEP is down. 3.5 times means that 3 CCM PDUs have
     * been lost.
     */
    uint32_t sec = (attr->CCMinterval / 10 * 35) / 1000;
    uint32_t usec = ((attr->CCMinterval / 10 * 35) % 1000) * 1000;
    NetIf::updateTimeFromNow(rMEPdb[rMEPid].rMEPwhile, sec, usec);

    return (EXIT_SUCCESS);
}

/*
 * This task is to handle received CFM packets and react accordingly 
 */
void ErpsEngine::task() {
    struct cfmhdr *cfmhdr;

    // For the packet received for processing
    Dot1ag *dot1ag = NULL;
    uint8_t *data;

    /* The main loop of this NetIf */
    int loop = 0;
    while (1) {
        cout << endl << *this << " :: In loop: will wait ... " << endl;
        unique_lock<mutex> ul(*(this->mutex_));
        this->cond_->wait(ul);

        /* to process each packet in the rxBuffer */
        int size = this->rxBuffer.size();
        for (int i = 0; i < size; i++) {
            dot1ag = this->rxBuffer.front();
            cout << endl << *this << " index: " << i << " :: Received Dot1ag packet" << endl;
            //            dot1ag->printPacket();

            data = dot1ag->getPacketData();
            cfmhdr = CFMHDR(data);
            switch (cfmhdr->opcode) {
                case CFM_CCM:
                    cout << " :: This is a CFM CCM packet ..." << endl;
                    processCcm(netIf0Cfg_, data);
                    break;
                case CFM_LBM:
                    cout << " :: This is a CFM LBM packet with tid: " <<
                            dot1ag->getTransId() << endl;
                    /* Now build responde and send out*/
                    if (EXIT_SUCCESS == Dot1agLbm::convertDotagLbm2Lbr(dot1ag,
                            this->netIf0_->getLocalMac())) {
                        this->netIf0_->sendPacket(dot1ag);
                        cout << " :: Sent CFM LBR packet Successfully with tid: " <<
                                dot1ag->getTransId() << endl;
                    }
                    break;
                case CFM_LBR:
                    cout << " :: This is a CFM LBR packet ..." << endl;
                    if (netIf0Cfg_.dot1agLbm != NULL) {
                        //dot1agLbm->printPacket();
                        if (EXIT_SUCCESS == netIf0Cfg_.dot1agLbm->cfm_matchlbr(data)) {
                            cout << " :: Good - This CFM LBR matched the LBM we sent with tid: " <<
                                    dot1ag->getTransId() << endl;
                        }
                    }

                    break;
                case CFM_LTM:
                    cout << " :: This is a CFM LTM packet ..." << endl;
                    break;
                case CFM_RAPS:
                    cout << " :: This is a R-APS packet ..." << endl;
                    if (netIf0Cfg_.dot1agRAps != NULL) {
                        //dot1agRAps->printPacket();
                        if (netIf0Cfg_.dot1agRAps->cfmMatchRAps(data)) {
                            cout << "  :: R-APS matched " << endl;
                        }
                    }
                    break;
                default:
                    break;
            }

            /* 
             * To-do: the packet has been process so it needs to be deleted 
             */
            this->rxBuffer.pop_front();
            delete dot1ag;
        }

        ul.unlock();
        loop++;
    }

}

ostream & operator<<(ostream& os, const ErpsEngine & ee) {
    os << "[" + ee.name_ + "(tid: " << this_thread::get_id() << ")]:: rx size: " << ee.rxBuffer.size() << endl;
    return os;
}

void ErpsEngine::sendDot1agPacket(Dot1ag *dot1ag, uint32_t seq) {
    int status = EXIT_SUCCESS;

    if (dot1ag == NULL) {
        return;
    }

    if (typeid (*dot1ag) == typeid (Dot1agCcm)) {
        dot1ag->setTransId(seq);
        cout << "  [TaskCfm]:: going to send CCM with seq: " << seq << endl;
    } else if (typeid (*dot1ag) == typeid (Dot1agLbm)) {
        dot1ag->setTransId(seq);
        cout << *this << "  [TaskCfm]:: going to send LBM with seq: " << seq << endl;
    }

    status = this->netIf0_->sendPacket(dot1ag);

    if (status == EXIT_SUCCESS) {
        cout << *this << "  [TaskCfm]:: Sent successfully" << endl;
    } else {
        cout << *this << "  [TaskCfm]:: Failed in sending" << endl;
    }

}

/*
 * To-do: using SIGALARM for scheduling periodically sending CCM/LBM messages 
 */
void ErpsEngine::scheduleTimer() {
    struct sigaction act;
    struct itimerval tval;

    /* define signal handler */
    act.sa_handler = &timeout_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* set timer to INTERVAL seconds */
    tval.it_interval.tv_usec = 0;
    tval.it_interval.tv_sec = 1;
    tval.it_value.tv_usec = 0;
    tval.it_value.tv_sec = 1;
    if (setitimer(ITIMER_REAL, &tval, NULL) < 0) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }

}

/*
 * Periodically sending CCM/LBMs if configred so
 */
void ErpsEngine::TaskCfm::task() {
    int status = EXIT_SUCCESS;
    struct timeval now, next_ccm;
    uint32_t seq = 0;

    /* schedule next CCM to be sent to now */
    gettimeofday(&next_ccm, NULL);

    while (1) {
        gettimeofday(&now, NULL);

        if (cfm_timevalcmp(next_ccm, now, <)) {
            /* Needs to skip CCMSkips of CCMs */
            if ((seq % (this->CCMSkips + 1)) == 0) {
                erpsEngine->sendDot1agPacket(erpsEngine->netIf0Cfg_.dot1agCcm, seq);
                erpsEngine->sendDot1agPacket(erpsEngine->netIf0Cfg_.dot1agLbm, seq);
            }
            seq++;
            NetIf::updateTimeFromNow(next_ccm, CCMinterval / 1000,
                    (CCMinterval % 1000) * 1000);
        }

        /* has one of the remote MEP timers run out? */
        status = this->erpsEngine->checkRMEPdb(this->erpsEngine->netIf0Cfg_);
        if (status == EXIT_FAILURE) {
            /* some mac is down */
            cout << "  :: mac is down so send out R-APS SF message ..." << endl;
            this->erpsEngine->netIf0_->sendPacket(this->erpsEngine->netIf0Cfg_.dot1agRAps);
            cout << "  :: R-APS SF sent " << endl;
        }

        /* To-do: sleep ms for now, and better solution might be using signal */
        usleep(NetIf::WAKEUP / 1000);
    }

}
