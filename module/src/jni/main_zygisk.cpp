#include <string>
#include <cstring>
#include <cstdio>
#include <sys/mman.h>

#include "inject.h"
#include "log.h"
#include "zygisk.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// Define hook for memfd_create
static int (*orig_memfd_create)(const char *name, unsigned int flags) = nullptr;
static int my_memfd_create(const char *name, unsigned int flags) {
    if (name && strstr(name, "jit-cache-zygiskfrida")) {
        const char *new_name = "jit-cache";
        return orig_memfd_create(new_name, flags);
    }
    return orig_memfd_create(name, flags);
}

// Define hook for fgets to strip out memfd mappings from any maps reader
static char* (*orig_fgets)(char *str, int num, FILE *stream) = nullptr;
static char* my_fgets(char *str, int num, FILE *stream) {
    char *line;
    while (true) {
        line = orig_fgets(str, num, stream);
        if (!line) return line;
        if (strstr(line, "memfd:")) continue;
        break;
    }
    return line;
}

class MyModule : public zygisk::ModuleBase {
 public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        // register hook for memfd_create to hide jit-cache naming
        api->pltHookRegister(".*", "memfd_create", (void*) my_memfd_create, (void**)&orig_memfd_create);
        // register hook for fgets to strip out memfd entries in /proc/self/maps
        api->pltHookRegister(".*", "fgets", (void*) my_fgets, (void**)&orig_fgets);
        api->pltHookCommit();
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *raw_app_name = env->GetStringUTFChars(args->nice_name, nullptr);

        std::string app_name = std::string(raw_app_name);
        this->env->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        if (!check_and_inject(app_name)) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

 private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
