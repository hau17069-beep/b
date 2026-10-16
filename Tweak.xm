// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <dlfcn.h>
#import <dirent.h>
#import <UIKit/UIKit.h>
#import <string.h>

// ==========================================
// KIỂM TRA CALLER: NẾU LÀ ROOTHIDE INFRA -> CHO PHÉP
// ==========================================
static bool isCallerRootHide() {
    void *caller = __builtin_return_address(0);
    if (!caller) return false;
    
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname) {
        const char *fname = info.dli_fname;
        if (strstr(fname, "roothide")     ||
            strstr(fname, "libinjector")  ||
            strstr(fname, "ellekit")      ||
            strstr(fname, "libroot")      ||
            strstr(fname, "systemhook")   ||
            strstr(fname, "AutoPatches")  ||
            strstr(fname, "TweakInject")  ||
            strstr(fname, "LCProtectionRecon")) {
            return true;
        }
    }
    return false;
}

// ==========================================
// KIỂM TRA ĐƯỜNG DẪN ĐÁNG NGỜ
// ==========================================
static bool isSuspicious(const char *path) {
    if (!path) return false;
    
    // Nếu caller là RootHide infra -> cho phép hết
    if (isCallerRootHide()) return false;
    
    // ----- CHẶN BẤT KỲ ĐƯỜNG DẪN NÀO CHỨA .jbroot -----
    // (Đây là fix chính cho vấn đề bị phát hiện)
    if (strstr(path, ".jbroot")) return true;
    if (strstr(path, "TweakInject")) return true;
    if (strstr(path, "DynamicPatches")) return true;
    if (strstr(path, "roothide")) return true;
    
    // ----- Dấu vết jailbreak cổ điển -----
    const char *classic[] = {
        "Cydia.app", "MobileSubstrate", "CydiaSubstrate",
        "/etc/apt", "/usr/sbin/sshd", "/usr/bin/ssh",
        "/var/lib/dpkg", "/var/cache/apt", "/var/lib/apt",
        "/private/var/lib/apt", "sshd_config", "ssh-keysign",
        "libellekit", "libhooker", "Choicy", "NSLogViewer",
        "Shadow.plist", "gpsmasterplugin", "AutoPickFoody",
        "LCProtectionRecon", "zzzzHeiBaoLib",
        "/bin/bash", "/usr/bin/ssh", "/usr/sbin/sshd"
    };
    for (size_t i = 0; i < sizeof(classic)/sizeof(classic[0]); i++) {
        if (strstr(path, classic[i])) return true;
    }
    return false;
}

// ==========================================
// HOOK CÁC HÀM FILE SYSTEM (mở rộng)
// ==========================================
%hookf(int, stat, const char *path, struct stat *buf) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isSuspicious(path)) return NULL;
    return %orig;
}

%hookf(DIR *, opendir, const char *path) {
    if (isSuspicious(path)) return NULL;
    return %orig;
}

%hookf(ssize_t, readlink, const char *path, char *buf, size_t bufsize) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

// ==========================================
// HOOK OBJECTIVE-C (mở rộng)
// ==========================================
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspicious([path UTF8String])) return NO;
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && isSuspicious([path UTF8String])) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path && isSuspicious([path UTF8String])) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (path && isSuspicious([path UTF8String])) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
%end

%hook NSData
+ (id)dataWithContentsOfFile:(NSString *)path {
    if (path && isSuspicious([path UTF8String])) return nil;
    return %orig;
}
+ (id)dataWithContentsOfFile:(NSString *)path options:(NSUInteger)mask error:(NSError **)errorPtr {
    if (path && isSuspicious([path UTF8String])) {
        if (errorPtr) *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:4 userInfo:nil];
        return nil;
    }
    return %orig;
}
%end

%hook NSString
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (path && isSuspicious([path UTF8String])) return NO;
    return %orig;
}
- (NSData *)dataUsingEncoding:(NSStringEncoding)enc {
    return %orig;
}
%end
