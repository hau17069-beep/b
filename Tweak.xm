// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <dirent.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <string.h>

// ==========================================
// KIỂM TRA CALLER: ROOTHIDE INFRA -> CHO PHÉP
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
            strstr(f, "TweakInject") || strstr(f, "LCProtectionRecon")) {
            return true;
        }
    }
    return false;
}

// ==========================================
// KIỂM TRA ĐƯỜNG DẪN ĐÁNG NGỜ
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    if (isCallerRootHide()) return false;
    
    if (strstr(path, ".jbroot")) return true;
    if (strstr(path, "TweakInject")) return true;
    if (strstr(path, "DynamicPatches")) return true;
    if (strstr(path, "roothide")) return true;
    
    const char *classic[] = {
        "Cydia.app", "MobileSubstrate", "CydiaSubstrate",
        "/etc/apt", "/usr/sbin/sshd", "/usr/bin/ssh",
        "/var/lib/dpkg", "/var/cache/apt", "/var/lib/apt",
        "/private/var/lib/apt", "sshd_config", "ssh-keysign",
        "libellekit", "libhooker", "Choicy", "NSLogViewer",
        "Shadow.plist", "gpsmasterplugin", "AutoPickFoody",
        "LCProtectionRecon", "zzzzHeiBaoLib", "/bin/bash"
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
        "MSHook", "substrate", "ellekit", "libhooker",
        "roothide", "fishhook", "Frida", "Cydia"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(sym, bad[i])) return true;
    }
    return false;
}

// ==========================================
// HOOK FILE SYSTEM (C)
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
%hookf(DIR *, opendir, const char *path) {
    if (isSuspiciousPath(path)) return NULL;
    return %orig;
}
%hookf(ssize_t, readlink, const char *path, char *buf, size_t bufsize) {
    if (isSuspiciousPath(path)) return -1;
    return %orig;
}

// ==========================================
// HOOK NSFileManager & NSData
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
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path && isSuspiciousPath([path UTF8String])) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
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
// HOOK SYSCALL (chỉ chặn khi caller KHÔNG phải RootHide)
// ==========================================
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        if (!isCallerRootHide()) {
            // Giả vờ không có tiến trình nào
            if (oldlenp) *oldlenp = 0;
            return 0;
        }
    }
    return %orig;
}

// ==========================================
// HOOK DLSYM (lọc symbol cụ thể)
// ==========================================
%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (isSuspiciousSymbol(symbol)) return NULL;
    return %orig;
}

// ==========================================
// HOOK GETENV (ẩn DYLD_INSERT_LIBRARIES)
// ==========================================
%hookf(char *, getenv, const char *name) {
    if (name && !isCallerRootHide()) {
        if (strstr(name, "DYLD_INSERT") ||
            strstr(name, "DYLD_LIBRARY") ||
            strstr(name, "DYLD_FRAMEWORK")) {
            return NULL;
        }
    }
    return %orig;
}

// ==========================================
// HOOK DYLD IMAGE ENUMERATION
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *name = %orig;
    if (name && !isCallerRootHide()) {
        if (strstr(name, ".jbroot") ||
            strstr(name, "TweakInject") ||
            strstr(name, "roothide") ||
            strstr(name, "ellekit") ||
            strstr(name, "libhooker") ||
            strstr(name, "Choicy") ||
            strstr(name, "NSLogViewer")) {
            return "/usr/lib/libSystem.B.dylib"; // Trả về path hệ thống sạch
        }
    }
    return name;
}

// ==========================================
// HOOK URL SCHEME
// ==========================================
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSString *s = url.scheme.lowercaseString;
        if ([s isEqualToString:@"cydia"] ||
            [s isEqualToString:@"sileo"] ||
            [s isEqualToString:@"zbra"]  ||
            [s isEqualToString:@"filza"]) {
            return NO;
        }
    }
    return %orig;
}
%end
