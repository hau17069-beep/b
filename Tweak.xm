// Tweak.xm - Full Bypass v4
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
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
#import <string.h>

// ==========================================
// EXTERN DECLARATIONS
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern "C" kern_return_t mach_vm_region(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    vm_region_flavor_t flavor,
    vm_region_info_t info,
    mach_msg_type_number_t *infoCnt,
    mach_port_t *object_name);
extern "C" kern_return_t mach_vm_region_recurse(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    natural_t *nesting_depth,
    vm_region_recurse_info_t info,
    mach_msg_type_number_t *infoCnt);

// ==========================================
// CALLER CHECK
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
// PATH CHECK
// ==========================================
static bool isSuspiciousPath(const char *path) {
    if (!path) return false;
    if (isCallerRootHide()) return false;
    
    if (strstr(path, ".jbroot")) return true;
    if (strstr(path, "TweakInject")) return true;
    if (strstr(path, "DynamicPatches")) return true;
    if (strstr(path, "roothide")) return true;
    if (strstr(path, "libinjector")) return true;
    if (strstr(path, "systemhook")) return true;
    
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
        "roothide", "fishhook", "Frida", "Cydia", "TweakInject",
        "libinjector", "systemhook"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strstr(sym, bad[i])) return true;
    }
    return false;
}

// ==========================================
// DYLD NAME MAPPER (nhất quán index->path)
// ==========================================
static bool isJbImageName(const char *name) {
    if (!name) return false;
    return strstr(name, ".jbroot")    != NULL ||
           strstr(name, "TweakInject") != NULL ||
           strstr(name, "roothide")    != NULL ||
           strstr(name, "ellekit")     != NULL ||
           strstr(name, "Choicy")      != NULL ||
           strstr(name, "NSLogViewer") != NULL ||
           strstr(name, "LCProtectionBypass") != NULL ||
           strstr(name, "AutoPickFoody") != NULL ||
           strstr(name, "AutoPatches") != NULL ||
           strstr(name, "libroot.dylib") != NULL ||
           strstr(name, "systemhook")  != NULL ||
           strstr(name, "libinjector") != NULL;
}

// Bảng path hệ thống hợp lệ (unique)
static const char *g_fakePaths[] = {
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/system/libdispatch.dylib",
    "/usr/lib/system/libsystem_kernel.dylib",
    "/usr/lib/system/libsystem_pthread.dylib",
    "/usr/lib/system/libsystem_c.dylib",
    "/usr/lib/system/libsystem_malloc.dylib",
    "/usr/lib/libc++.1.dylib",
    "/usr/lib/libc++abi.dylib",
    "/usr/lib/libnetwork.dylib",
    "/usr/lib/libcompression.dylib",
    "/usr/lib/libsqlite3.dylib",
    "/usr/lib/libxml2.2.dylib",
    "/usr/lib/libz.1.dylib",
    "/usr/lib/libbz2.1.0.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/usr/lib/libresolv.9.dylib",
    "/usr/lib/libarchive.2.dylib",
    "/usr/lib/libenergytrace.dylib",
    "/usr/lib/libprotobuf.dylib"
};
static const int g_fakePathCount = sizeof(g_fakePaths) / sizeof(g_fakePaths[0]);

// Map index -> fake path (nhất quán)
static const char *fakeNameForIndex(uint32_t idx) {
    return g_fakePaths[idx % g_fakePathCount];
}

// ==========================================
// SECTION 1: DYLD
// ==========================================
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *real = %orig;
    if (real && !isCallerRootHide() && isJbImageName(real)) {
        return fakeNameForIndex(image_index);
    }
    return real;
}

%hookf(uint32_t, _dyld_image_count, void) {
    return %orig;
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    return %orig;
}

// ==========================================
// SECTION 2: DLADDR (fix mismatch với _dyld_get_image_name)
// ==========================================
%hookf(int, dladdr, const void *addr, Dl_info *info) {
    int ret = %orig;
    if (ret && info && info->dli_fname && !isCallerRootHide()) {
        if (isJbImageName(info->dli_fname)) {
            // Đổi tên hiển thị cho khớp với _dyld_get_image_name
            // Tìm index của image này để trả về cùng fake path
            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const struct mach_header *hdr = _dyld_get_image_header(i);
                if (hdr == (const struct mach_header *)info->dli_fbase) {
                    info->dli_fname = fakeNameForIndex(i);
                    break;
                }
            }
        }
    }
    return ret;
}

// ==========================================
// SECTION 3: FILE SYSTEM
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
// SECTION 4: DYLD LOADING + DLSYM
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
// SECTION 5: SYSCALL
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

%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && !isCallerRootHide()) {
        if (strstr(name, "kern.proc") ||
            strstr(name, "kern.argmax") ||
            strstr(name, "security.mac")) {
            if (oldlenp) *oldlenp = 0;
            return 0;
        }
    }
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    if (!isCallerRootHide()) return -1;
    return %orig;
}

// ==========================================
// SECTION 6: TASK_INFO (fix vector TASK_DYLD_INFO)
// ==========================================
%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    if (!isCallerRootHide()) {
        // TASK_DYLD_INFO = 17, TASK_DYLD_INFO_COUNT = 5
        if (flavor == 17) {
            // Trả về KERN_FAILURE để app không đọc được dyld info
            return KERN_FAILURE;
        }
    }
    return %orig;
}

// ==========================================
// SECTION 7: MACH_VM_REGION (fix memory scan)
// ==========================================
%hookf(kern_return_t, mach_vm_region, vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    if (!isCallerRootHide() && flavor == VM_REGION_BASIC_INFO_64) {
        kern_return_t ret = %orig;
        // Nếu region có tên path chứa dấu hiệu JB → giả vờ hết region
        if (ret == KERN_SUCCESS && info) {
            vm_region_basic_info_data_64_t *basic = (vm_region_basic_info_data_64_t *)info;
            const char *name = (const char *)basic->offset;
            // Không có tên path trong basic info, chỉ có offset
            // → Không lọc được; trả về bình thường
        }
        return ret;
    }
    return %orig;
}

%hookf(kern_return_t, mach_vm_region_recurse, vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    return %orig;
}

// ==========================================
// SECTION 8: PROCESS ENUM
// ==========================================
%hookf(int, proc_pidinfo, int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (!isCallerRootHide()) {
        if (flavor == 1 || flavor == 13 || flavor == 17) {
            return 0;
        }
    }
    return %orig;
}
%hookf(int, proc_listpids, uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    if (!isCallerRootHide()) return 0;
    return %orig;
}

// ==========================================
// SECTION 9: ENV VARS
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
// SECTION 10: OBJECTIVE-C
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
// SECTION 11: OBJC RUNTIME
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
        if (strstr(name, "Shadow") || strstr(name, "Choicy")) return nil;
    }
    return %orig;
}

// ==========================================
// SECTION 12: UIApplication URL schemes
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
