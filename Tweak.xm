// Tweak.xm - Full Bypass v4-fixed
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <unistd.h>
#import <dlfcn.h>
#import <dirent.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <string.h>

// ==========================================
// EXTERN DECLARATIONS
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);

// ==========================================
// CALLER CHECK - KHÔNG dùng dladdr vì có thể gây đệ quy
// Chỉ check chuỗi tên từ __builtin_return_address + đọc symbol
// ==========================================
// Đơn giản hóa: bỏ hẳn caller check cho các hook không cần thiết
// Các hook liên quan tới _dyld_*, chúng ta tự kiểm tra nội bộ

// ==========================================
// PATH CHECK
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    
    if (strstr(path, ".jbroot")) return true;
    if (strstr(path, "TweakInject")) return true;
    if (strstr(path, "DynamicPatches")) return true;
    if (strstr(path, "roothide")) return true;
    if (strstr(path, "libinjector")) return true;
    if (strstr(path, "systemhook")) return true;
    
    const char *jbApps[] = {
        "Cydia.app", "RST.app", "NZT.app", "Sileo.app", "Filza.app",
        "TouchSprite", "Flybird", "AWZ.app", "ALS.app", "AXJ.app",
        "AMG.app", "hdFaker", "zorro.app", "YOY.app", "ASA.app",
        "ShellCloud", "CraneApplication", "HeiBao"
    };
    for (size_t i = 0; i < sizeof(jbApps)/sizeof(jbApps[0]); i++) {
        if (strstr(path, jbApps[i])) return true;
    }
    
    const char *debugPaths[] = {
        "/Developer/usr/bin/DTDeviceArbitration",
        "/Developer/usr/bin/ScreenShotr",
        "/Developer/usr/lib/libXCTestBundleInject.dylib",
        "/Developer/usr/bin/debugserver",
        "/Developer/usr/lib"
    };
    for (size_t i = 0; i < sizeof(debugPaths)/sizeof(debugPaths[0]); i++) {
        if (strstr(path, debugPaths[i])) return true;
    }
    
    if (strstr(path, "heibao.service.plist")) return true;
    if (strstr(path, "zzzzHeiBaoLib")) return true;
    if (strstr(path, "HeiBaoService")) return true;
    
    if (strcmp(path, "/var/jb") == 0) return true;
    if (strcmp(path, "/private/preboot/jb") == 0) return true;
    if (strstr(path, "/var/containers/Bundle/xina")) return true;
    
    const char *classic[] = {
        "/bin/su", "/usr/sbin/sshd", "/usr/bin/ssh", "/etc/apt",
        "/usr/lib/libellekit", "libhooker", "/Library/MobileSubstrate"
    };
    for (size_t i = 0; i < sizeof(classic)/sizeof(classic[0]); i++) {
        if (strstr(path, classic[i])) return true;
    }
    
    return false;
}

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
// DYLD NAME MAPPER
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
// SECTION 1: DYLD
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && isJbImageName(real)) {
        return g_fakePaths[image_index % g_fakePathCount];
    }
    return real;
}

%hookf(uint32_t, _dyld_image_count, void) {
    return %orig;
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    return %orig;
}

// ==========================================
// SECTION 2: FILE SYSTEM
// ==========================================
%hookf(int, stat, const char *path, struct stat *buf) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}
%hookf(int, lstat, const char *path, struct stat *buf) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}
%hookf(int, statfs, const char *path, struct statfs *buf) {
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
%hookf(DIR *, opendir, const char *path) {
    if (isSuspiciousPath(path)) return NULL;
    return %orig;
}
%hookf(ssize_t, readlink, const char *path, char *buf, size_t bufsize) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}

// ==========================================
// SECTION 3: DYLD LOADING + DLSYM
// ==========================================
%hookf(void *, dlopen, const char *path, int mode) {
    if (isSuspiciousPath(path)) return NULL;
    return %orig;
}
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

%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        if (strstr(name, "kern.proc") ||
            strstr(name, "kern.argmax") ||
            strstr(name, "security.mac")) {
            if (oldlenp) *oldlenp = 0;
            return 0;
        }
    }
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    return -1;
}

// ==========================================
// SECTION 5: TASK_INFO
// ==========================================
%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    // TASK_DYLD_INFO = 17
    if (flavor == 17) {
        return KERN_FAILURE;
    }
    return %orig;
}

// ==========================================
// SECTION 6: PROCESS ENUM
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

// ==========================================
// SECTION 7: ENV VARS
// ==========================================
%hookf(char *, getenv, const char *name) {
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
// SECTION 8: OBJECTIVE-C
// ==========================================
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspiciousPath([path UTF8String])) return NO;
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && isSuspiciousPath([path UTF8String])) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (path && isSuspiciousPath([path UTF8String])) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path && isSuspiciousPath([path UTF8String])) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
- (NSData *)contentsAtPath:(NSString *)path {
    if (path && isSuspiciousPath([path UTF8String])) return nil;
    return %orig;
}
%end

%hook NSData
+ (id)dataWithContentsOfFile:(NSString *)path {
    if (path && isSuspiciousPath([path UTF8String])) return nil;
    return %orig;
}
+ (id)dataWithContentsOfFile:(NSString *)path options:(NSUInteger)mask error:(NSError **)errorPtr {
    if (path && isSuspiciousPath([path UTF8String])) {
        if (errorPtr) *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
%end

// ==========================================
// SECTION 9: OBJC RUNTIME
// ==========================================
%hookf(Class, objc_getClass, const char *name) {
    if (name) {
        if (strstr(name, "Shadow") || strstr(name, "Choicy") ||
            strstr(name, "LCProtectionRecon")) {
            return nil;
        }
    }
    return %orig;
}

// ==========================================
// SECTION 10: UIApplication URL schemes
// ==========================================
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSString *s = url.scheme.lowercaseString;
        if ([s isEqualToString:@"cydia"] ||
            [s isEqualToString:@"sileo"] ||
            [s isEqualToString:@"zbra"] ||
            [s isEqualToString:@"filza"]) {
            return NO;
        }
    }
    return %orig;
}
%end
