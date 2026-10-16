// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <string.h>

// ==========================================
// HÀM KIỂM TRA ĐƯỜNG DẪN ĐÁNG NGỜ (CHỈ TẬP TRUNG VÀO ROOTHIDE)
// ==========================================
static bool isSuspicious(const char *path) {
    if (!path) return false;
    
    // Chỉ chặn các dấu vết đặc trưng của RootHide và tweak
    // KHÔNG chặn các đường dẫn hệ thống chung chung như /bin/bash, /usr/sbin/sshd
    const char *blacklist[] = {
        ".jbroot",          // Dấu vết đặc trưng nhất của RootHide
        "roothide",
        "TweakInject",      // Nơi chứa các tweak
        "Choicy",
        "NSLogViewer",
        "Shadow.plist",
        "gpsmasterplugin.plist",
        "AutoPickFoody",
        "libellekit",
        "libhooker",
        "LCProtectionRecon",
        "zzzzHeiBaoLib",
        "AutoPatches.dylib"
    };
    
    for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (strstr(path, blacklist[i])) return true;
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
// 2. HOOK OBJECTIVE-C (NSFileManager)
// ==========================================

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && isSuspicious([path UTF8String])) {
        return NO;
    }
    return %orig;
}
%end
