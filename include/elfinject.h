#ifndef __ELFINJECT_H__
#define __ELFINJECT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "cuckoo.h"
int injectELF(cuckoo_context *context);

#ifdef __cplusplus
}
#endif
#endif