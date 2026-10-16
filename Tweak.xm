// Tweak.xm - Full Bypass v11 (Whitelist NSLogViewer + ellekit caller)
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <string.h>

// ==========================================
// EXTERN
// ==========================================
extern "C" kern_return_t task_info(task_name_t target_task, task_flavor_t task_flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt);
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);

// ==========================================
// CALLER CHECK - dùng dladdr (KHÔNG hook dladdr nên không đệ quy)
// ==========================================
static bool isCallerWhitelisted() {
    void *caller = __builtin_return_address(0);
    if (!caller) return false;
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname) {
        const char *f = info.dli_fname;
        // NSLogViewer và mọi thứ nó dùng
        if (strstr(f, "NSLogViewer"))   return true;
        if (strstr(f, "libellekit"))    return true;
        if (strstr(f, "libinjector"))   return true;
        // Tweak của chúng ta
        if (strstr(f, "LCProtectionRecon")) return true;
        if (strstr(f, "LCProtectionBypass")) return true;
        // RootHide infra
        if (strstr(f, "roothide"))      return true;
        if (strstr(f, "libroot"))       return true;
        if (strstr(f, "systemhook"))    return true;
        if (strstr(f, "AutoPatches"))   return true;
    }
    return false;
}

// ==========================================
// DYLD NAME - chỉ ẩn tên file cụ thể
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    
    // Whitelist - LUÔN hiển thị
    if (strstr(name, "NSLogViewer"))       return false;
    if (strstr(name, "libellekit"))        return false;
    if (strstr(name, "libinjector"))       return false;
    if (strstr(name, "LCProtectionRecon")) return false;
    if (strstr(name, "LCProtectionBypass")) return false;
    if (strstr(name, "systemhook"))        return false;
    
    // Blacklist - chỉ tên file cụ thể
    if (strstr(name, "roothideinit.dylib"))  return true;
    if (strstr(name, "roothidepatch.dylib")) return true;
    if (strstr(name, "libroothide.dylib"))   return true;
    if (strstr(name, "libroot.dylib"))       return true;
    if (strstr(name, "AutoPatches.dylib"))   return true;
    if (strstr(name, "Choicy.dylib"))        return true;
    if (strstr(name, "AutoPickFoody.dylib")) return true;
    
    return false;
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
// HOOK 2: TASK_INFO - cho phép whitelisted caller
// ==========================================
%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    if (flavor == 17) { // TASK_DYLD_INFO
        if (isCallerWhitelisted()) return %orig;
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
        "jbroot", "substrate", "libhooker",
        "roothide", "fishhook", "Frida", "Cydia"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(sym, bad[i])) return true;
    }
    return false;
}

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (isCallerWhitelisted()) return %orig;
    if (isSuspiciousSymbol(symbol)) return NULL;
    return %orig;
}

// ==========================================
// HOOK 4: SYSCALL
// ==========================================
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (isCallerWhitelisted()) return %orig;
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        if (oldlenp) *oldlenp = 0;
        return 0;
    }
    return %orig;
}

%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (isCallerWhitelisted()) return %orig;
    if (name) {
        if (strstr(name, "kern.proc") || strstr(name, "kern.argmax")) {
            if (oldlenp) *oldlenp = 0;
            return 0;
        }
    }
    return %orig;
}

// ==========================================
// HOOK 5: CSOPS - cho phép whitelisted caller
// ==========================================
%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    if (isCallerWhitelisted()) return %orig;
    return -1;
}

// ==========================================
// HOOK 6: PROC ENUMERATION - cho phép whitelisted caller
// ==========================================
%hookf(int, proc_pidinfo, int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (isCallerWhitelisted()) return %orig;
    if (flavor == 1 || flavor == 13 || flavor == 17) {
        return 0;
    }
    return %orig;
}

%hookf(int, proc_listpids, uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    if (isCallerWhitelisted()) return %orig;
    return 0;
}
