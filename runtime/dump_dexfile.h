#ifndef DUMP_DEXFILE_H_
#define DUMP_DEXFILE_H_

#include "dex/dex_file.h"
#include <android/log.h>

#define LOG_TAG    "UDEX"
#define LOGV(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

namespace art {

void dump_dexfile(const DexFile * dexfile);

}  // namespace art

#endif  // DUMP_DEXFILE_H_
