// Tweak.xm - Full Bypass v7 (Minimal)
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <string.h>

// ==========================================
// DYLD NAME MAPPING
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    return strstr(name, ".jbroot")           != NULL ||
           strstr(name, "TweakInject")       != NULL ||
           strstr(name, "roothide")          != NULL ||
           strstr(name, "ellekit")           != NULL ||
           strstr(name, "Choicy")            != NULL ||
           strstr(name, "NSLogViewer")       != NULL ||
           strstr(name, "LCProtectionRecon") != NULL ||
           strstr(name, "AutoPickFoody")     != NULL ||
           strstr(name, "AutoPatches")       != NULL ||
           strstr(name, "libroot.dylib")     != NULL ||
           strstr(name, "systemhook")        != NULL ||
           strstr(name, "libinjector")       != NULL;
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
// HOOK 1: _dyld_get_image_name (ẩn dylib)
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && isJbImageName(real)) {
        return g_fakePaths[image_index % g_fakePathCount];
    }
    return real;
}

// ==========================================
// HOOK 2: dlsym (ẩn symbol)
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
// HOOK 3: sysctl KERN_PROC
// ==========================================
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        if (oldlenp) *oldlenp = 0;
        return 0;
    }
    return %orig;
}
