#include <jni.h>
#include <string>
#include <dirent.h>
#include <sys/system_properties.h>
#include "dump_dexfile.h"

const uint8_t kDexMagic[] = { 'd', 'e', 'x', '\n' };
const uint8_t kCDexMagic[] = { 'c', 'd', 'e', 'x' };

bool IsValidDexMagic(const uint8_t* magic) {
    return (memcmp(magic, kDexMagic, sizeof(kDexMagic)) == 0);
}

bool IsValidCDexMagic(const uint8_t* magic) {
    return (memcmp(magic, kCDexMagic, sizeof(kCDexMagic)) == 0);
}

std::string getPropertyString(const char * key, const char * default_val) {
    char property_value[PROP_VALUE_MAX] = {0};

    int length = __system_property_get(key, property_value);
    if (length <= 0 || property_value[0] == '\0') {
        return default_val;
    }
    return property_value;
}

bool getPropertyBoolean(const char * key, bool default_val) {
    char property_value[PROP_VALUE_MAX] = {0};

    int length = __system_property_get(key, property_value);
    if (length <= 0 || property_value[0] == '\0') {
        return default_val;
    }
    std::string value = property_value;
    if (value == "false" || value == "0") {
        return false;
    } else {
        return true;
    }
}

bool isDirectoryExists(const char * path) {
    if (path == nullptr || strlen(path) == 0) {
        return false;
    }

    DIR* dir = opendir(path);
    if (dir != nullptr) {
        closedir(dir);
        return true;
    }

    return false;
}

void dump_dexfile(const DexFile * dexfile) {
    if (dexfile == nullptr) {
        return ;
    }
    bool isEnabled = getPropertyBoolean("persist.udex.b4", false);
    if (!isEnabled) {
        return ;
    }
    std::string packet_name = getPropertyString("persist.udex.s1", "");
    if (packet_name.empty()) {
        return ;
    }

    std::string dir_path = "/data/data/" + packet_name;
    if (!isDirectoryExists(dir_path.c_str())) {
        return ;
    }

    std::string dump_path = dir_path + "/dump";
    if (!isDirectoryExists(dir_path.c_str())) {
        return ;
    }

    try {
        if (IsValidDexMagic(&dexfile->header_->magic_[0])) {
            LOGV("dump dex file, begin: %p, size: %x", dexfile->begin_, (int)dexfile->size_);
            save_dex_file(dump_path, dexfile);
        } else if (IsValidCDexMagic(&dexfile->header_->magic_[0])) {
            LOGV("pass cdex file, begin: %p, size: %x", dexfile->begin_, (int)dexfile->size_);
        } else {
            LOGV("invalid magic, begin: %p, size: %x", dexfile->begin_, (int)dexfile->size_);
        }
    } catch(...) {
        LOGV("save_dex_file occue except!");
    }
}
