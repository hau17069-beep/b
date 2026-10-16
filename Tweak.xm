// Tweak.xm - Full Recon (Anti-recursion, Anti-RootHide-crash)
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
#import <stdarg.h>

// ==========================================
// REENTRANCY-PROOF LOGGER
// ==========================================
static __thread int g_log_depth = 0;

static void RECON_LOG(const char *category, const char *fmt, ...) {
    if (g_log_depth > 0) return;
    g_log_depth++;
    
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    NSLog(@"[RECON][%s] %s", category, buf);
    
    g_log_depth--;
}

// ==========================================
// EXTERN DECLARATIONS
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);

// ==========================================
// SECTION 1: FILE SYSTEM
// ==========================================

%hookf(int, stat, const char *path, struct stat *buf) {
    if (path) RECON_LOG("FS", "stat: %s", path);
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (path) RECON_LOG("FS", "lstat: %s", path);
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (path) RECON_LOG("FS", "access: %s", path);
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (path) RECON_LOG("FS", "fopen: %s", path);
    return %orig;
}

%hookf(DIR *, opendir, const char *path) {
    if (path) RECON_LOG("FS", "opendir: %s", path);
    return %orig;
}

%hookf(ssize_t, readlink, const char *path, char *buf, size_t bufsize) {
    if (path) RECON_LOG("FS", "readlink: %s", path);
    return %orig;
}

// ==========================================
// SECTION 2: SYSCALL & PROCESS
// ==========================================

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2) {
        RECON_LOG("SYSCTL", "name[0]=%d name[1]=%d", name[0], name[1]);
    } else if (namelen >= 1) {
        RECON_LOG("SYSCTL", "name[0]=%d namelen=%u", name[0], namelen);
    }
    return %orig;
}

%hookf(int, ptrace, int request, pid_t pid, caddr_t addr, int data) {
    RECON_LOG("PROC", "ptrace request=%d pid=%d", request, pid);
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    RECON_LOG("PROC", "csops pid=%d ops=%u", pid, ops);
    return %orig;
}

%hookf(int, proc_pidinfo, int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    RECON_LOG("PROC", "proc_pidinfo pid=%d flavor=%d", pid, flavor);
    return %orig;
}

%hookf(int, proc_listpids, uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    RECON_LOG("PROC", "proc_listpids type=%u", type);
    return %orig;
}

// ==========================================
// SECTION 3: DYNAMIC LINKING
// ==========================================

%hookf(void *, dlopen, const char *path, int mode) {
    if (path) RECON_LOG("DYLD", "dlopen: %s", path);
    return %orig;
}

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (symbol) {
        // Chỉ log symbol nghi vấn để giảm nhiễu
        if (strstr(symbol, "MSHook") || strstr(symbol, "substrate") ||
            strstr(symbol, "ellekit") || strstr(symbol, "roothide") ||
            strstr(symbol, "fishhook") || strstr(symbol, "Frida") ||
            strstr(symbol, "Cydia") || strstr(symbol, "jbroot") ||
            strstr(symbol, "hook") || strstr(symbol, "Tweak") ||
            strstr(symbol, "Choicy") || strstr(symbol, "Shadow")) {
            RECON_LOG("DYLD", "dlsym SUSPICIOUS: %s", symbol);
        }
    }
    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *name = %orig;
    if (name) {
        if (strstr(name, ".jbroot") || strstr(name, "TweakInject") ||
            strstr(name, "roothide") || strstr(name, "ellekit") ||
            strstr(name, "Choicy") || strstr(name, "NSLogViewer") ||
            strstr(name, "Shadow")) {
            RECON_LOG("DYLD", "image[%u] = %s", image_index, name);
        }
    }
    return name;
}

// ==========================================
// SECTION 4: OBJECTIVE-C RUNTIME
// ==========================================

%hookf(Class, objc_getClass, const char *name) {
    if (name) {
        if (strstr(name, "Shadow") || strstr(name, "Choicy") ||
            strstr(name, "LCProtection") || strstr(name, "AutoPick") ||
            strstr(name, "Tweak") || strstr(name, "Jailbreak") ||
            strstr(name, "JB") || strstr(name, "Hook")) {
            RECON_LOG("OBJC", "objc_getClass SUSPICIOUS: %s", name);
        }
    }
    return %orig;
}

// ==========================================
// SECTION 5: NSFileManager
// ==========================================

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path) RECON_LOG("NSFM", "fileExistsAtPath: %s", [path UTF8String]);
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path) RECON_LOG("NSFM", "fileExistsAtPath:isDir: %s", [path UTF8String]);
    return %orig;
}
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path) RECON_LOG("NSFM", "contentsOfDirectoryAtPath: %s", [path UTF8String]);
    return %orig;
}
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (path) RECON_LOG("NSFM", "attributesOfItemAtPath: %s", [path UTF8String]);
    return %orig;
}
%end

// ==========================================
// SECTION 6: NSURLSession
// ==========================================

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    NSString *url = request.URL.absoluteString;
    NSString *method = request.HTTPMethod;
    RECON_LOG("NET", "%s %s", [method UTF8String], [url UTF8String]);
    
    // Log body nếu có và chứa từ khóa nghi vấn
    NSData *body = request.HTTPBody;
    if (body) {
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bodyStr) {
            NSString *lower = bodyStr.lowercaseString;
            if ([lower containsString:@"jailbreak"] || [lower containsString:@"root"] ||
                [lower containsString:@"device"] || [lower containsString:@"security"] ||
                [lower containsString:@"risk"] || [lower containsString:@"sign"]) {
                RECON_LOG("NET-BODY", "%s", [bodyStr UTF8String]);
            }
        }
    }
    
    return %orig;
}
%end

// ==========================================
// SECTION 7: UIApplication URL schemes
// ==========================================

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) RECON_LOG("UIAPP", "canOpenURL: %s", [url.absoluteString UTF8String]);
    return %orig;
}
%end
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && strstr(real, ".jbroot")) {
        // Trả về đường dẫn giả trông giống hệ thống
        return "/usr/lib/libSystem.B.dylib";
    }
    return real;
}
