/*
 * @brief: CFM R-APS PDU Encapsulation with type/length media
 *
 *    Copyright (c) 2017
 *    HCL Technologies Ltd.
 *    All rights reserved.
 *
 * Created on March 7, 2017
 */

#ifndef _DOT1AG_CCM_H_
#define _DOT1AG_CCM_H_

#include <string>
using namespace std;

#include "ieee8021ag.h"
#include "Dot1ag.h"

class Dot1agCcm : public Dot1ag {
public:

    Dot1agCcm(const Dot1agAttr *attr);

    virtual ~Dot1agCcm() {
    };
    
    void addCcm(uint8_t md_level, const char *md, const char *ma,
        uint16_t mepid, uint32_t CCIsentCCMs);
    
    int cfmMatchCcm(const uint8_t *data) const;
    
private:    

};

#endif /* The end of #ifndef _DOT1AG_CCM_H_ */

