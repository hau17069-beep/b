// Tweak.xm - Full Bypass v12
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <dirent.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <string.h>

// ==========================================
// EXTERN
// ==========================================
extern "C" kern_return_t task_info(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
extern "C" int csops(pid_t, unsigned int, void *, size_t);
extern "C" int proc_pidinfo(int, int, uint64_t, void *, int);
extern "C" int proc_listpids(uint32_t, uint32_t, void *, int);

// ==========================================
// THREAD-LOCAL GUARDS (chống đệ quy)
// ==========================================
static __thread int g_dyld_recurse = 0;
static __thread int g_caller_depth = 0;

// ==========================================
// CALLER CHECK
// ==========================================
static bool isCallerWhitelisted() {
    if (g_caller_depth > 0) return false;
    g_caller_depth++;
    
    void *caller = __builtin_return_address(0);
    bool result = false;
    
    if (caller) {
        Dl_info info;
        if (dladdr(caller, &info) && info.dli_fname) {
            const char *f = info.dli_fname;
            if (strstr(f, "NSLogViewer"))       result = true;
            else if (strstr(f, "libellekit"))   result = true;
            else if (strstr(f, "libinjector"))  result = true;
            else if (strstr(f, "LCProtectionRecon")) result = true;
            else if (strstr(f, "LCProtectionBypass")) result = true;
            else if (strstr(f, "roothide"))     result = true;
            else if (strstr(f, "libroot"))      result = true;
            else if (strstr(f, "systemhook"))   result = true;
            else if (strstr(f, "AutoPatches"))  result = true;
        }
    }
    
    g_caller_depth--;
    return result;
}

// ==========================================
// DYLD NAME - ẩn path chứa .jbroot khi caller là LCProtection
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    // Ẩn MỌI path chứa .jbroot hoặc các tên JB cụ thể
    if (strstr(name, ".jbroot")) return true;
    if (strstr(name, "roothideinit.dylib"))  return true;
    if (strstr(name, "roothidepatch.dylib")) return true;
    if (strstr(name, "libroothide.dylib"))   return true;
    if (strstr(name, "libroot.dylib"))       return true;
    if (strstr(name, "AutoPatches.dylib"))   return true;
    if (strstr(name, "Choicy.dylib"))        return true;
    if (strstr(name, "AutoPickFoody.dylib")) return true;
    if (strstr(name, "libinjector.dylib"))   return true;
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
// HOOK 1: _dyld_get_image_name (quan trọng nhất)
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if (g_dyld_recurse > 0) return %orig;
    g_dyld_recurse++;
    
    const char *real = %orig;
    bool hide = false;
    
    if (real && isJbImageName(real)) {
        // Nếu caller là whitelisted (NSLogViewer tự tìm chính nó) -> trả path thật
        if (!isCallerWhitelisted()) {
            hide = true;
        }
    }
    
    g_dyld_recurse--;
    
    if (hide) return g_fakePaths[image_index % g_fakePathCount];
    return real;
}

// ==========================================
// HOOK 2: TASK_INFO
// ==========================================
%hookf(kern_return_t, task_info, task_name_t target, task_flavor_t flavor, task_info_t out, mach_msg_type_number_t *cnt) {
    if (flavor == 17 && !isCallerWhitelisted()) return KERN_FAILURE;
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

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    if (isCallerWhitelisted()) return %orig;
    return -1;
}

%hookf(int, proc_pidinfo, int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (isCallerWhitelisted()) return %orig;
    if (flavor == 1 || flavor == 13 || flavor == 17) return 0;
    return %orig;
}

%hookf(int, proc_listpids, uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    if (isCallerWhitelisted()) return %orig;
    return 0;
}

// ==========================================
// HOOK 5: FILE SYSTEM (thêm lại với caller check)
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    const char *bad[] = {
        // JB apps cổ điển
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Filza.app", "/Applications/RST.app",
        "/Applications/NZT.app", "/Applications/TouchSprite",
        "/Applications/Flybird", "/Applications/hdFaker",
        "/Applications/zorro.app", "/Applications/YOY.app",
        "/Applications/ASA.app", "/Applications/ShellCloud",
        "/Applications/HeiBao", "/Applications/AMG.app",
        "/Applications/ALS.app", "/Applications/AXJ.app",
        "/Applications/AWZ.app", "/Applications/CraneApplication",
        // Classic JB
        "/bin/su", "/usr/sbin/sshd", "/usr/bin/ssh", "/etc/apt",
        "/var/jb", "/private/preboot/jb",
        "/Library/MobileSubstrate",
        "libellekit", "libhooker",
        // Debug
        "/Developer/usr/bin/debugserver",
        "/Developer/usr/lib/libXCTestBundleInject",
        "/Developer/usr/bin/DTDeviceArbitration",
        // HeiBao
        "zzzzHeiBaoLib", "HeiBaoService", "heibao.service.plist"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(path, bad[i])) return true;
    }
    return false;
}

%hookf(int, stat, const char *path, struct stat *buf) {
    if (isCallerWhitelisted()) return %orig;
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (isCallerWhitelisted()) return %orig;
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (isCallerWhitelisted()) return %orig;
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isCallerWhitelisted()) return %orig;
    if (isSuspiciousPath(path)) return NULL;
    return %orig;
}

// ==========================================
// HOOK 6: GETENV
// ==========================================
%hookf(char *, getenv, const char *name) {
    if (isCallerWhitelisted()) return %orig;
    if (name) {
        if (strstr(name, "DYLD_INSERT") ||
            strstr(name, "DYLD_LIBRARY") ||
            strstr(name, "DYLD_FRAMEWORK")) {
            return NULL;
        }
    }
    return %orig;
}

// ==========================================
// HOOK 7: NSFileManager
// ==========================================
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && !isCallerWhitelisted() && isSuspiciousPath([path UTF8String])) return NO;
    return %orig;
}
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (path && !isCallerWhitelisted() && isSuspiciousPath([path UTF8String])) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
%end
