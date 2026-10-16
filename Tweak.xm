// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <string.h>

// ==========================================
// HÀM KIỂM TRA ĐƯỜNG DẪN ĐÁNG NGỜ
// Chỉ chặn TÊN FILE CỤ THỂ, không chặn cả thư mục
// ==========================================
static bool isSuspicious(const char *path) {
    if (!path) return false;
    
    const char *blacklist[] = {
        // Các tweak cụ thể mà LCProtection đang tìm
        "NSLogViewer",
        "Choicy.dylib",
        "Shadow.plist",
        "gpsmasterplugin.plist",
        "AutoPickFoody",
        "LCProtectionRecon",
        "zzzzHeiBaoLib",
        
        // Các dấu vết jailbreak cổ điển
        "Cydia.app",
        "MobileSubstrate",
        "CydiaSubstrate",
        "libhooker"
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
