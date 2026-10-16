// Tweak.xm - Full Bypass v6
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <string.h>

// ==========================================
// EXTERN
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// ==========================================
// THREAD-LOCAL GUARDS
// ==========================================
static __thread int g_in_getcwd = 0;
static __thread int g_check_depth = 0;

// ==========================================
// PATH CHECK
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    
    // Nếu đang trong getcwd hoặc đệ quy nội bộ -> cho phép
    if (g_in_getcwd > 0) return false;
    if (g_check_depth > 0) return false;
    
    g_check_depth++;
    bool result = false;
    
    // Chỉ check tên file cụ thể (KHÔNG check "TweakInject/" vì đó là CWD)
    const char *badNames[] = {
        "roothideinit.dylib", "roothidepatch.dylib", "libroothide.dylib",
        "libinjector.dylib", "libellekit.dylib", "libroot.dylib",
        "Choicy.dylib", "NSLogViewer.dylib", "LCProtectionRecon.dylib",
        "AutoPatches.dylib", "AutoPickFoody.dylib", "Shadow.dylib",
        "systemhook",
        "Cydia.app", "Sileo.app", "Filza.app", "RST.app", "NZT.app",
        "TouchSprite", "Flybird", "hdFaker",
        "/Developer/usr/bin/debugserver",
        "/Developer/usr/lib/libXCTestBundleInject",
        "/Developer/usr/bin/DTDeviceArbitration",
        "zzzzHeiBaoLib", "HeiBaoService", "heibao.service.plist",
        "/bin/su", "/usr/sbin/sshd", "/usr/bin/ssh", "/etc/apt",
        "libhooker", "/Library/MobileSubstrate"
    };
    for (size_t i = 0; i < sizeof(badNames)/sizeof(badNames[0]); i++) {
        if (strstr(path, badNames[i])) { result = true; break; }
    }
    
    if (!result) {
        if (strcmp(path, "/var/jb") == 0) result = true;
        else if (strcmp(path, "/private/preboot/jb") == 0) result = true;
        else if (strstr(path, "/var/containers/Bundle/xina")) result = true;
    }
    
    g_check_depth--;
    return result;
}

static bool isSuspiciousSymbol(const char *sym) {
    if (!sym) return false;
    if (g_in_getcwd > 0) return false;
    const char *bad[] = {
        "jbroot", "MSHook", "substrate", "ellekit", "libhooker",
        "roothide", "fishhook", "Frida", "Cydia", "TweakInject",
        "libinjector", "systemhook"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(sym, bad[i])) return true;
    }
    return false;
}

// ==========================================
// DYLD NAME MAPPING
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    return strstr(name, ".jbroot")    != NULL ||
           strstr(name, "TweakInject") != NULL ||
           strstr(name, "roothide")    != NULL ||
           strstr(name, "ellekit")     != NULL ||
           strstr(name, "Choicy")      != NULL ||
           strstr(name, "NSLogViewer") != NULL ||
           strstr(name, "LCProtectionRecon") != NULL ||
           strstr(name, "AutoPickFoody") != NULL ||
           strstr(name, "AutoPatches") != NULL ||
           strstr(name, "libroot.dylib") != NULL ||
           strstr(name, "systemhook")  != NULL ||
           strstr(name, "libinjector") != NULL;
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
// SECTION 0: HOOK GETCWD TRƯỚC TIÊN (fix đệ quy)
// ==========================================
%hookf(char *, getcwd, char *buf, size_t size) {
    g_in_getcwd++;
    char *r = %orig;
    g_in_getcwd--;
    return r;
}

// ==========================================
// SECTION 1: DYLD
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && isJbImageName(real)) {
        return g_fakePaths[image_index % g_fakePathCount];
    }
    return real;
}

// ==========================================
// SECTION 2: FILE SYSTEM (minimal)
// ==========================================
%hookf(int, stat, const char *path, struct stat *buf) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}
%hookf(int, lstat, const char *path, struct stat *buf) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}
%hookf(int, access, const char *path, int mode) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}
%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isSuspiciousPath(path)) return NULL;
    return %orig;
}

// ==========================================
// SECTION 3: DLSYM
// ==========================================
%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (isSuspiciousSymbol(symbol)) return NULL;
    return %orig;
}

// ==========================================
// SECTION 4: SYSCALL
// ==========================================
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        if (oldlenp) *oldlenp = 0;
        return 0;
    }
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    return -1;
}

// ==========================================
// SECTION 5: OBJC (NSFileManager)
// ==========================================
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspiciousPath([path UTF8String])) return NO;
    return %orig;
}
%end
