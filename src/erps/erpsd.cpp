/* 
 * File:   erpsd.cpp
 * Author: wangj
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 * 
 *  Created on March 7, 2017, 4:08 PM
 * 
 */

#include "dot1ag/net_common.h"

#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "dot1ag/Dot1agLbm.h"
#include "dot1ag/Dot1agRAps.h"
#include "dot1ag/Dot1agCcm.h"

#include "dot1ag/NetIf.h"
#include "erps/ErpsEngine.h"

static void usage() {
    fprintf(stderr, "\n  usage: erpsd -i interface \n\n"
            "    [-m MEPID(11)] \n"
            "    [-t target mac address] \n"
            "    [-r ring id(1)] \n"
            "    [-m MEPID] \n"
            "    [-v vlan (0)] [-l mdlevel (1)]\n"
            "    [-s CCM-interval (1000) 100|1000|10000|60000|600000] \n"
            "    [-S CCM-skips (0)]\n"
            "    [-d maintenance-domain(HCL)]\n"
            "    [-a maintenance-association(HCL_ERPS)]\n"
            "    [-V verbose] \n\n"
            "  Notes: \n\n"
            "  - Interface is required via -i \n"
            "  - If -m specified, it will continually sending CCMs; \n"
            "  - If -t specified, it will continually sending LBMs; \n"
            "  - If none of the above 2 specified, it will behave like a daemon, \n"
            "    just waiting for Dot1ag messages. \n\n"
            );

    exit(EXIT_FAILURE);
}

/*
 * Main function
 */
int main(int argc, char** argv) {

    int ch;
    int status = -1;

    Dot1agAttr attr;

    /* parse command line options */
    while ((ch = getopt(argc, argv, "hi:l:v:c:r:t:m:s:S:d:a:V")) != -1) {
        switch (ch) {
            case 'h':
                usage();
                break;
            case 'i':
                attr.ifname = optarg;
                break;
            case 'l':
                attr.md_level = atoi(optarg);
                break;
            case 'v':
                attr.vlan = atoi(optarg);
                break;
            case 'r':
                attr.ring_id = atoi(optarg);
                break;
            case 't':
                attr.remoteMac = optarg;
                break;
            case 'm':
                attr.mepid = atoi(optarg);
                break;
            case 's':
                attr.CCMinterval = atoi(optarg);
                break;
            case 'S':
                attr.CCMSkips = atoi(optarg);
                break;
            case 'd':
                attr.md = optarg;
                break;
            case 'a':
                attr.ma = optarg;
                break;
            case 'V':
                attr.verbose = 1;
                break;
            case '?':
            default:
                cout << "Invalid option provided: " << ch << endl;
                usage();
        }
    }


    if (argc - optind != 0) {
        usage();
    }


    /* check for mandatory '-i' flag */
    if (attr.ifname == NULL) {
        cout << "-i interface is required." << endl;
        usage();
    }
    
    /* check for valid '-t' flag */
    /*
     * 10 ms is not supported because it is probably a too short
     * interrupt time for most Unix based systems.
     */
    switch (attr.CCMinterval) {
        case 100:
        case 1000:
        case 10000:
        case 60000:
        case 600000:
            break;
        default:
            fprintf(stderr, "Supported CCM interval times are:\n");
            fprintf(stderr, "100, 1000, 10000, 60000, 600000 ms\n");
            exit(EXIT_FAILURE);
    }


    cout << "Hello from ERPSd!" << endl;

    NetIf nif(attr.ifname);

    /* Handling ERPS and CFM messages */
    ErpsEngine erpsEngine(&nif, &attr);
    
    thread *thread_netif;
    nif.init();
    thread_netif = nif.start();

    /* Will block here until the engine stops */
    erpsEngine.startService();

    thread_netif->join();

    return 0;
}

