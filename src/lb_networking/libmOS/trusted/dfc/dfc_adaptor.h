#ifndef DFC_ADPATOR_H
#define DFC_ADPATOR_H

#include "dfc.h"

class DFCAdaptor
{
 public:
    
  DFCAdaptor();
    
  ~DFCAdaptor();

  int init(const unsigned char* pattern_pool, int *pattern_length, int size);
    
  int process(const unsigned char* payload, int length);

 private:
  DFC_STRUCTURE* m_dfc;
};

#endif
