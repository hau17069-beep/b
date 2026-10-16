// Tweak.xm - Full Bypass v10 (Fix NSLogViewer)
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
// DYLD NAME - CHỈ ẨN TÊN FILE CỤ THỂ, KHÔNG ẨN PATH CHUNG
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    
    // ============ WHITELIST - LUÔN HIỂN THỊ ============
    // NSLogViewer - để nó tự tìm thấy chính nó
    if (strstr(name, "NSLogViewer")) return false;
    // Tweak của chúng ta - để Choicy có thể inject
    if (strstr(name, "LCProtectionRecon")) return false;
    if (strstr(name, "LCProtectionBypass")) return false;
    // ELLEKIT + INJECTOR: nếu ẩn sẽ làm NSLogViewer không hook được UI
    if (strstr(name, "libellekit")) return false;
    if (strstr(name, "libinjector")) return false;
    if (strstr(name, "systemhook")) return false;
    
    // ============ BLACKLIST - ẨN CỤ THỂ TỪNG FILE ============
    // RootHide infra
    if (strstr(name, "roothideinit.dylib"))  return true;
    if (strstr(name, "roothidepatch.dylib")) return true;
    if (strstr(name, "libroothide.dylib"))   return true;
    if (strstr(name, "libroot.dylib"))       return true;
    if (strstr(name, "AutoPatches.dylib"))   return true;
    // Tweaks cụ thể (không phải NSLogViewer)
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
// HOOK 2: TASK_INFO (TASK_DYLD_INFO)
// ==========================================
%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    if (flavor == 17) { // TASK_DYLD_INFO
        return KERN_FAILURE;
    }
    return %orig;
}

// ==========================================
// HOOK 3: DLSYM - bỏ "hook" và "MSHook" để không phá NSLogViewer
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

// ==========================================
// HOOK 5: CSOPS
// ==========================================
%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    return -1;
}

// ==========================================
// HOOK 6: PROC ENUMERATION
// ==========================================
%hookf(int, proc_pidinfo, int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (flavor == 1 || flavor == 13 || flavor == 17) {
        return 0;
    }
    return %orig;
}

%hookf(int, proc_listpids, uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    return 0;
}
