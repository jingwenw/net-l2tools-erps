/*
 * @brief: CFM PDU Encapsulation with type/length media
 * 
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 */

#ifndef _DOT1AG_LTM_H_
#define _DOT1AG_LTM_H_

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "ieee8021ag.h"

class Dot1agLtm: public Dot1ag {
public:
    
    Dot1agLtm(){        
    };
    
    virtual ~Dot1agLtm() {
    };
    
    void
    cfm_addltm(uint32_t transID, uint8_t ttl, uint8_t *localmac, uint8_t *remotemac);

    void
    cfm_ltm_setttl(uint8_t ttl);

    void
    cfm_ltm_settransid(uint32_t trans_id);

    void
    cfm_addltr(uint32_t transID, uint8_t ttl, uint8_t action);

    int
    cfm_matchltr(uint8_t *dst, uint16_t vlan, uint8_t md_level,
            uint32_t trans_id, int *hit_target);


    
private:
};

#endif /* The end of #ifndef _DOT1AG_LTM_H_ */

