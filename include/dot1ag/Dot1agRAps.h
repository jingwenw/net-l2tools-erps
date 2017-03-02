/*
 * @brief: CFM R-APS PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _DOT1AG_R_APS_H_
#define _DOT1AG_R_APS_H_

#include "ieee8021ag.h"
#include "Dot1ag.h"

class Dot1agRAps : public Dot1ag {
public:

    Dot1agRAps(const Dot1agAttr *attr);

    static uint8_t rApsDstMac[ETHER_ADDR_LEN];
    
    void addRAps(uint8_t request, uint8_t *nid);
    
    int cfmMatchRAps(const uint8_t *data) const;
    
private:    

};

#endif /* The end of #ifndef _DOT1AG_R_APS_H_ */

