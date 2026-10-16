// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <string.h>

// ==========================================
// HÀM KIỂM TRA ĐƯỜNG DẪN ĐÁNG NGỜ
// ==========================================
static bool isSuspicious(const char *path) {
    if (!path) return false;
    
    const char *blacklist[] = {
        "Cydia", "jbroot", "roothide", "MobileSubstrate", "substrate",
        "TweakInject", "libellekit", "libroot", "zzzzHeiBaoLib",
        "sshd", "ssh", "apt", "/bin/bash", "Choicy", "NSLogViewer",
        "LCProtectionRecon", "Shadow.plist", "gpsmasterplugin.plist",
        "AutoPatches.dylib", "LCProtection", "libhooker", "ellekit"
    };
    
    for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (strstr(path, blacklist[i])) return true;
    }
    return false;
}

static bool isSuspiciousSymbol(const char *symbol) {
    if (!symbol) return false;
    
    const char *blacklist[] = {
        "MSHook", "substrate", "ellekit", "roothide", "fishhook",
        "Frida", "libhooker", "Cydia"
    };
    
    for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (strstr(symbol, blacklist[i])) return true;
    }
    return false;
}

// ==========================================
// 1. HOOK CÁC HÀM C CẤP THẤP (File System)
// ==========================================

%hookf(int, stat, const char *path, struct stat *buf) {
    if (isSuspicious(path)) return -1; // Giả vờ file không tồn tại
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isSuspicious(path)) return NULL; // Giả vờ mở file thất bại
    return %orig;
}

// ==========================================
// 2. HOOK SYSCALL (Chặn quét tiến trình)
// ==========================================

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        return -1; // Giả vờ lỗi
    }
    return %orig;
}

// ==========================================
// 3. HOOK DLSYM (Ẩn symbol tweak)
// ==========================================

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (isSuspiciousSymbol(symbol)) return NULL;
    return %orig;
}

// ==========================================
// 4. HOOK OBJECTIVE-C (NSFileManager)
// ==========================================

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspicious([path UTF8String])) {
        return NO;
    }
    return %orig;
}
%end
