// Tweak.xm - Full Bypass v8
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <string.h>

// ==========================================
// EXTERN
// ==========================================
extern "C" kern_return_t task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt);
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// ==========================================
// DYLD NAME CHECK (KHÔNG ẩn NSLogViewer để nó hoạt động)
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    return strstr(name, ".jbroot")           != NULL ||
           strstr(name, "roothide")          != NULL ||
           strstr(name, "ellekit")           != NULL ||
           strstr(name, "Choicy")            != NULL ||
           strstr(name, "LCProtectionRecon") != NULL ||
           strstr(name, "AutoPickFoody")     != NULL ||
           strstr(name, "AutoPatches")       != NULL ||
           strstr(name, "libroot.dylib")     != NULL ||
           strstr(name, "systemhook")        != NULL ||
           strstr(name, "libinjector")       != NULL;
           // LƯU Ý: KHÔNG ẩn "NSLogViewer", "TweakInject" (chung) để tweak khác hoạt động
}

static const char *g_fakePaths[] = {
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/system/libdispatch.dylib",
    "/usr/lib/system/libsystem_kernel.dylib",
    "/usr/lib/system/libsystem_pthread.dylib",
    "/usr/lib/system/libsystem_c.dylib",
    "/usr/lib/system/libsystem_malloc.dylib",
    "/usr/lib/libc++.1.dylib",
    "/usr/lib/libc++abi.dylib",
    "/usr/lib/libnetwork.dylib",
    "/usr/lib/libcompression.dylib",
    "/usr/lib/libsqlite3.dylib",
    "/usr/lib/libxml2.2.dylib",
    "/usr/lib/libz.1.dylib",
    "/usr/lib/libbz2.1.0.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/usr/lib/libresolv.9.dylib",
    "/usr/lib/libarchive.2.dylib",
    "/usr/lib/libenergytrace.dylib",
    "/usr/lib/libprotobuf.dylib"
};
static const int g_fakePathCount = sizeof(g_fakePaths) / sizeof(g_fakePaths[0]);

// ==========================================
// HOOK 1: _dyld_get_image_name
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && isJbImageName(real)) {
        return g_fakePaths[image_index % g_fakePathCount];
    }
    return real;
}

// ==========================================
// HOOK 2: TASK_INFO - chặn TASK_DYLD_INFO (vector ẩn)
// ==========================================
%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    // TASK_DYLD_INFO = 17
    if (flavor == 17) {
        return KERN_FAILURE;
    }
    return %orig;
}

// ==========================================
// HOOK 3: DLSYM
// ==========================================
static bool isSuspiciousSymbol(const char *sym) {
    if (!sym) return false;
    const char *bad[] = {
        "jbroot", "MSHook", "substrate", "ellekit", "libhooker",
        "roothide", "fishhook", "Frida", "Cydia", "TweakInject"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(sym, bad[i])) return true;
    }
    return false;
}

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (isSuspiciousSymbol(symbol)) return NULL;
    return %orig;
}

// ==========================================
// HOOK 4: SYSCALL
// ==========================================
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        if (oldlenp) *oldlenp = 0;
        return 0;
    }
    return %orig;
}

%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        if (strstr(name, "kern.proc") || strstr(name, "kern.argmax")) {
            if (oldlenp) *oldlenp = 0;
            return 0;
        }
    }
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    return -1;
}
