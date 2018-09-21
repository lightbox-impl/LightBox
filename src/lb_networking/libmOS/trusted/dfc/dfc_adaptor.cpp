#include "dfc_adaptor.h"
//#include "../Enclave.h"
#include <string>

DFCAdaptor::DFCAdaptor() {
  m_dfc = DFC_New();
}

int DFCAdaptor::init(const unsigned char* pattern_pool, int *pattern_length, int size) {
  unsigned char* pattern = const_cast<unsigned char*>(pattern_pool);
  for (int i = 0; i < size; ++i) {
    //printf("add pattern of lenth %d\n", pattern_length[i]);
    DFC_AddPattern(m_dfc,
                   pattern,
                   pattern_length[i],
                   0, i);
    pattern += pattern_length[i];
  }

  return DFC_Compile(m_dfc);
}

DFCAdaptor::~DFCAdaptor() {
    DFC_FreeStructure(m_dfc);
}

// TODO
void match_action(unsigned char*, uint32_t *, uint32_t) {
    /*switch (pid) {
      case 0:
        printf("pattern *attack* found!\n");
        break;
      case 1:
        printf("pattern *cityu* found!\n");
        break;
      case 2:
        printf("pattern *9221* found!\n");
        break;
      default:
        ;
    }*/
}

int DFCAdaptor::process(const unsigned char* payload, int length) {
    return DFC_Search(m_dfc, 
               const_cast<unsigned char*>(payload),
               length, 
               match_action);
}

