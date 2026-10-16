// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <string.h>
#import <execinfo.h>

// ==========================================
// KIỂM TRA CALLER CÓ PHẢI LÀ ROOTHIDE INFRASTRUCTURE KHÔNG
// ==========================================
static bool isCallerRootHide() {
    void *caller = __builtin_return_address(1);
    if (!caller) return false;
    
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname) {
        const char *fname = info.dli_fname;
        // Nếu caller là RootHide infra, KHÔNG chặn
        if (strstr(fname, "libroothide") ||
            strstr(fname, "libinjector") ||
            strstr(fname, "roothideinit") ||
            strstr(fname, "roothidepatch") ||
            strstr(fname, "libroot.dylib") ||
            strstr(fname, "ellekit") ||
            strstr(fname, "AutoPatches") ||
            strstr(fname, "systemhook")) {
            return true;
        }
    }
    return false;
}

// ==========================================
// HÀM KIỂM TRA ĐƯỜNG DẪN ĐÁNG NGỜ
// ==========================================
static bool isSuspicious(const char *path) {
    if (!path) return false;
    
    // Nếu caller là RootHide, luôn cho phép
    if (isCallerRootHide()) return false;
    
    // Chỉ chặn các dấu vết đặc trưng của tweak và Cydia
    // KHÔNG chặn toàn bộ .jbroot vì RootHide cần dùng
    const char *blacklist[] = {
        "TweakInject/",         // Nơi chứa tweak
        "TweakInject",
        "Choicy",
        "NSLogViewer",
        "Shadow.plist",
        "gpsmasterplugin.plist",
        "AutoPickFoody",
        "LCProtectionRecon",
        "zzzzHeiBaoLib",
        "Cydia.app",
        "MobileSubstrate"
    };
    
    for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (strstr(path, blacklist[i])) return true;
    }
    return false;
}

// ==========================================
// 1. HOOK STAT
// ==========================================
%hookf(int, stat, const char *path, struct stat *buf) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

// ==========================================
// 2. HOOK ACCESS
// ==========================================
%hookf(int, access, const char *path, int mode) {
    if (isSuspicious(path)) return -1;
    return %orig;
}

// ==========================================
// 3. HOOK FOPEN
// ==========================================
%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isSuspicious(path)) return NULL;
    return %orig;
}

// ==========================================
// 4. HOOK OBJECTIVE-C
// ==========================================
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspicious([path UTF8String])) {
        return NO;
    }
    return %orig;
}
%end
