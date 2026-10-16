// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/ptrace.h> // BẮT BUỘC: Thêm để fix lỗi 'ptrace'
#import <unistd.h>     // BẮT BUỘC: Thêm để fix lỗi 'access'
#import <dlfcn.h>
#import <UIKit/UIKit.h>

// ==========================================
// 1. HOOK CÁC HÀM C CẤP THẤP (File System)
// ==========================================

%hookf(int, stat, const char *path, struct stat *buf) {
    if (path) {
        // Chỉ log những file/thư mục nghi vấn để đỡ rối log
        if (strstr(path, "jbroot") || strstr(path, "Cydia") || strstr(path, "substrate") || 
            strstr(path, "roothide") || strstr(path, "ellekit") || strstr(path, "bin/bash") || 
            strstr(path, "ssh") || strstr(path, "apt") || strstr(path, "dpkg") || 
            strstr(path, "frida") || strstr(path, "MobileSubstrate")) {
            NSLog(@"[LC-RECON] stat -> %s", path);
        }
    }
    return %orig;
}

// ĐÃ XÓA HOOK statfs Ở ĐÂY ĐỂ TRÁNH LỖI BUILD

%hookf(int, access, const char *path, int mode) {
    if (path) {
        if (strstr(path, "jbroot") || strstr(path, "Cydia") || strstr(path, "substrate") || 
            strstr(path, "roothide") || strstr(path, "ellekit") || strstr(path, "bin/bash")) {
            NSLog(@"[LC-RECON] access -> %s", path);
        }
    }
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (path) {
        if (strstr(path, "jbroot") || strstr(path, "Cydia") || strstr(path, "substrate") || 
            strstr(path, "roothide") || strstr(path, "ellekit") || strstr(path, "bin/bash")) {
            NSLog(@"[LC-RECON] fopen -> %s", path);
        }
    }
    return %orig;
}

// ==========================================
// 2. HOOK SYSCALL (Check debugger, tiến trình)
// ==========================================

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = %orig;
    if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        NSLog(@"[LC-RECON] sysctl KERN_PROC called (Checking processes)");
    }
    return ret;
}

%hookf(int, ptrace, int request, pid_t pid, caddr_t addr, int data) {
    NSLog(@"[LC-RECON] ptrace called (Checking debugger)");
    return %orig;
}

// ==========================================
// 3. HOOK DLSYM (Tìm symbol của tweak/substrate)
// ==========================================

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (symbol) {
        if (strstr(symbol, "MSHook") || strstr(symbol, "substrate") || strstr(symbol, "ellekit") || 
            strstr(symbol, "roothide") || strstr(symbol, "fishhook") || strstr(symbol, "Frida")) {
            NSLog(@"[LC-RECON] dlsym -> %s", symbol);
        }
    }
    return %orig;
}

// ==========================================
// 4. HOOK OBJECTIVE-C (NSFileManager, UIApplication)
// ==========================================

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path) {
        if ([path containsString:@"jbroot"] || [path containsString:@"Cydia"] || 
            [path containsString:@"substrate"] || [path containsString:@"roothide"] || 
            [path containsString:@"ellekit"]) {
            NSLog(@"[LC-RECON] NSFileManager fileExistsAtPath -> %@", path);
        }
    }
    return %orig;
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSLog(@"[LC-RECON] canOpenURL -> %@", url.absoluteString);
    }
    return %orig;
}
%end
