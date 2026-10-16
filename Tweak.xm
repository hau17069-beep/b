// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <string.h>

// ==========================================
// KIỂM TRA CALLER CÓ PHẢI LÀ ROOTHIDE INFRA KHÔNG
// Nếu đúng -> cho phép, tránh crash RootHide
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
            strstr(fname, "TweakInject") ||
            strstr(fname, "LCProtectionRecon")) {
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
    
    // Nếu caller là RootHide infra -> cho phép hết
    if (isCallerRootHide()) return false;
    
    // ----- Nhóm 1: Đường dẫn chứa các thư mục tweak -----
    if (strstr(path, "TweakInject") ||
        strstr(path, "DynamicPatches")) {
        return true;
    }
    
    // ----- Nhóm 2: File .dylib cụ thể trong .jbroot -----
    if (strstr(path, ".jbroot")) {
        const char *specific[] = {
            "roothideinit.dylib",
            "roothidepatch.dylib",
            "libroothide.dylib",
            "libinjector.dylib",
            "libellekit.dylib",
            "libroot.dylib",
            "Choicy.dylib",
            "NSLogViewer.dylib",
            "LCProtectionRecon.dylib",
            "Shadow.dylib",
            "Shadow.plist",
            "AutoPickFoody.dylib",
            "gpsmasterplugin.plist"
        };
        for (size_t i = 0; i < sizeof(specific)/sizeof(specific[0]); i++) {
            if (strstr(path, specific[i])) return true;
        }
    }
    
    // ----- Nhóm 3: Dấu vết jailbreak cổ điển -----
    const char *classic[] = {
        "Cydia.app",
        "MobileSubstrate",
        "CydiaSubstrate",
        "/etc/apt",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/var/lib/dpkg",
        "/var/cache/apt",
        "sshd_config",
        "ssh-keysign",
        "zzzzHeiBaoLib"
    };
    for (size_t i = 0; i < sizeof(classic)/sizeof(classic[0]); i++) {
        if (strstr(path, classic[i])) return true;
    }
    
    return false;
}

// ==========================================
// HOOK CÁC HÀM FILE SYSTEM
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

// ==========================================
// HOOK OBJECTIVE-C
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
%end
