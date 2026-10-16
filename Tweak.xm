// Tweak.xm - Full Bypass v5 (Minimal, chống crash)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <dirent.h>
#import <mach-o/dyld.h>
#import <string.h>

// ==========================================
// EXTERN
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);

// ==========================================
// THREAD-LOCAL GUARD (tránh đệ quy)
// ==========================================
static __thread int g_check_depth = 0;

// ==========================================
// PATH CHECK - chỉ chặn pattern cụ thể, KHÔNG chặn .jbroot đơn thuần
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    if (g_check_depth > 0) return false;
    g_check_depth++;
    
    bool result = false;
    
    // Pattern cụ thể của RootHide/tweak (KHÔNG dùng ".jbroot" một mình)
    if (strstr(path, "TweakInject/"))            result = true;
    else if (strstr(path, "DynamicPatches/"))    result = true;
    else if (strstr(path, "roothideinit.dylib")) result = true;
    else if (strstr(path, "roothidepatch.dylib")) result = true;
    else if (strstr(path, "libroothide.dylib"))  result = true;
    else if (strstr(path, "libinjector.dylib"))  result = true;
    else if (strstr(path, "libellekit.dylib"))   result = true;
    else if (strstr(path, "libroot.dylib"))      result = true;
    else if (strstr(path, "Choicy.dylib"))       result = true;
    else if (strstr(path, "NSLogViewer.dylib"))  result = true;
    else if (strstr(path, "LCProtectionRecon.dylib")) result = true;
    else if (strstr(path, "AutoPatches.dylib"))  result = true;
    else if (strstr(path, "AutoPickFoody.dylib")) result = true;
    else if (strstr(path, "Shadow.dylib"))       result = true;
    else if (strstr(path, "systemhook"))         result = true;
    // JB apps
    else if (strstr(path, "Cydia.app"))          result = true;
    else if (strstr(path, "Sileo.app"))          result = true;
    else if (strstr(path, "Filza.app"))          result = true;
    else if (strstr(path, "RST.app"))            result = true;
    else if (strstr(path, "NZT.app"))            result = true;
    else if (strstr(path, "TouchSprite"))        result = true;
    else if (strstr(path, "Flybird"))            result = true;
    else if (strstr(path, "hdFaker"))            result = true;
    // Debug
    else if (strstr(path, "/Developer/usr/bin/debugserver")) result = true;
    else if (strstr(path, "/Developer/usr/lib/libXCTestBundleInject")) result = true;
    else if (strstr(path, "/Developer/usr/bin/DTDeviceArbitration")) result = true;
    // HeiBao
    else if (strstr(path, "zzzzHeiBaoLib"))      result = true;
    else if (strstr(path, "HeiBaoService"))      result = true;
    else if (strstr(path, "heibao.service.plist")) result = true;
    // Jailbreak paths
    else if (strcmp(path, "/var/jb") == 0)       result = true;
    else if (strcmp(path, "/private/preboot/jb") == 0) result = true;
    else if (strstr(path, "/var/containers/Bundle/xina")) result = true;
    // Classic
    else if (strstr(path, "/bin/su"))            result = true;
    else if (strstr(path, "/usr/sbin/sshd"))     result = true;
    else if (strstr(path, "/usr/bin/ssh"))       result = true;
    else if (strstr(path, "/etc/apt"))           result = true;
    else if (strstr(path, "libhooker"))          result = true;
    else if (strstr(path, "/Library/MobileSubstrate")) result = true;
    
    g_check_depth--;
    return result;
}

// ==========================================
// SYMBOL CHECK
// ==========================================
static bool isSuspiciousSymbol(const char *sym) {
    if (!sym) return false;
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
// DYLD IMAGE NAME MAPPER
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
// SECTION 1: DYLD (quan trọng nhất)
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && isJbImageName(real)) {
        return g_fakePaths[image_index % g_fakePathCount];
    }
    return real;
}

// ==========================================
// SECTION 2: FILE SYSTEM (chỉ 4 hàm an toàn)
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
// SECTION 5: OBJC (chỉ NSFileManager)
// ==========================================
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspiciousPath([path UTF8String])) return NO;
    return %orig;
}
%end
