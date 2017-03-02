/*
 * @brief: CFM_LBM PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _DOT1AG_LBM_H_
#define _DOT1AG_LBM_H_

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "ieee8021ag.h"
#include "Dot1ag.h"

class Dot1agLbm : public Dot1ag {
public:
    /* how many times need to wait before sending in waiting for response */
    static const int LBR_BACKLOG = 6;
    
    Dot1agLbm(const Dot1agAttr *attr);

    virtual ~Dot1agLbm() {
    };

    int cfm_matchlbr(const uint8_t *data);
    static int convertDotagLbm2Lbr(Dot1ag *lb, const uint8_t *localMac);

private:

};

#endif /* The end of #ifndef _DOT1AG_LBM_H_ */

