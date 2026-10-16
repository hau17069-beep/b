// Tweak.xm - Full Bypass v2
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
#import <string.h>

// ==========================================
// EXTERN DECLARATIONS (các hàm private của Apple)
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);

// ==========================================
// CALLER CHECK: nếu là RootHide infra -> cho phép
// ==========================================
static bool isCallerRootHide() {
    void *caller = __builtin_return_address(0);
    if (!caller) return false;
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname) {
        const char *f = info.dli_fname;
        if (strstr(f, "roothide")    || strstr(f, "libinjector") ||
            strstr(f, "ellekit")     || strstr(f, "libroot")     ||
            strstr(f, "systemhook")  || strstr(f, "AutoPatches") ||
            strstr(f, "TweakInject") || strstr(f, "LCProtectionBypass")) {
            return true;
        }
    }
    return false;
}

// ==========================================
// DANH SÁCH ĐEN: file & đường dẫn cần ẩn
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    if (isCallerRootHide()) return false;
    
    if (strstr(path, ".jbroot")) return true;
    if (strstr(path, "TweakInject")) return true;
    if (strstr(path, "DynamicPatches")) return true;
    if (strstr(path, "roothide")) return true;
    
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
    if (isCallerRootHide()) return false;
    const char *bad[] = {
        "jbroot", "MSHook", "substrate", "ellekit", "libhooker",
        "roothide", "fishhook", "Frida", "Cydia", "TweakInject"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(sym, bad[i])) return true;
    }
    return false;
}

// ==========================================
// SECTION 1: DYLD - QUAN TRỌNG NHẤT
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && !isCallerRootHide()) {
        if (strstr(real, ".jbroot") ||
            strstr(real, "TweakInject") ||
            strstr(real, "roothide") ||
            strstr(real, "ellekit") ||
            strstr(real, "Choicy") ||
            strstr(real, "NSLogViewer") ||
            strstr(real, "LCProtectionBypass") ||
            strstr(real, "AutoPatches") ||
            strstr(real, "libroot.dylib") ||
            strstr(real, "systemhook")) {
            return "/usr/lib/libSystem.B.dylib";
        }
    }
    return real;
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    return %orig;
}

%hookf(uint32_t, _dyld_image_count, void) {
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
        if (!isCallerRootHide()) {
            if (oldlenp) *oldlenp = 0;
            return 0;
        }
    }
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    if (!isCallerRootHide()) {
        return -1;
    }
    return %orig;
}

// ==========================================
// SECTION 5: OBJECTIVE-C
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
// SECTION 6: OBJC RUNTIME
// ==========================================
%hookf(Class, objc_getClass, const char *name) {
    if (name && !isCallerRootHide()) {
        if (strstr(name, "Shadow") || strstr(name, "Choicy") ||
            strstr(name, "LCProtectionRecon")) {
            return nil;
        }
    }
    return %orig;
}

%hookf(Class, objc_lookUpClass, const char *name) {
    if (name && !isCallerRootHide()) {
        if (strstr(name, "Shadow") || strstr(name, "Choicy")) {
            return nil;
        }
    }
    return %orig;
}

// ==========================================
// SECTION 7: UIApplication URL schemes
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
