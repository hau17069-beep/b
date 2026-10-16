// Tweak.xm - Full Recon
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/param.h>
#import <sys/proc.h>
#import <unistd.h>
#import <dlfcn.h>
#import <dirent.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
#import <spawn.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>

// ==========================================
// EXTERN DECLARATIONS
// ==========================================
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern "C" int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern "C" char ***_NSGetEnviron(void);
extern "C" char *getenv(const char *name);
extern "C" int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);

// Khai báo thủ công 2 hàm mach_vm (mach_vm.h bị iOS SDK vô hiệu hóa)
extern "C" kern_return_t mach_vm_region(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    vm_region_flavor_t flavor,
    vm_region_info_t info,
    mach_msg_type_number_t *infoCnt,
    mach_port_t *object_name
);

extern "C" kern_return_t mach_vm_region_recurse(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    natural_t *nesting_depth,
    vm_region_recurse_info_t info,
    mach_msg_type_number_t *infoCnt
);

// ==========================================
// SECTION 1: FILE SYSTEM (C APIs)
// ==========================================

%hookf(int, stat, const char *path, struct stat *buf) {
    if (path) NSLog(@"[FULL-RECON][FS] stat: %s", path);
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (path) NSLog(@"[FULL-RECON][FS] lstat: %s", path);
    return %orig;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
    if (path) NSLog(@"[FULL-RECON][FS] statfs: %s", path);
    return %orig;
}

%hookf(int, getfsstat, struct statfs *buf, int bufsize, int flags) {
    NSLog(@"[FULL-RECON][FS] getfsstat called (mount enumeration)");
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (path) NSLog(@"[FULL-RECON][FS] access: %s", path);
    return %orig;
}

%hookf(int, faccessat, int fd, const char *path, int mode, int flag) {
    if (path) NSLog(@"[FULL-RECON][FS] faccessat: %s", path);
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (path) NSLog(@"[FULL-RECON][FS] fopen: %s", path);
    return %orig;
}

%hookf(DIR *, opendir, const char *path) {
    if (path) NSLog(@"[FULL-RECON][FS] opendir: %s", path);
    return %orig;
}

%hookf(ssize_t, readlink, const char *path, char *buf, size_t bufsize) {
    if (path) NSLog(@"[FULL-RECON][FS] readlink: %s", path);
    return %orig;
}

%hookf(char *, realpath, const char *path, char *resolved) {
    if (path) NSLog(@"[FULL-RECON][FS] realpath: %s", path);
    return %orig;
}

// ==========================================
// SECTION 2: SYSCALL & PROCESS
// ==========================================

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2) {
        NSLog(@"[FULL-RECON][SYSCTL] sysctl name[0]=%d name[1]=%d namelen=%u", name[0], name[1], namelen);
    } else {
        NSLog(@"[FULL-RECON][SYSCTL] sysctl namelen=%u", namelen);
    }
    return %orig;
}

%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) NSLog(@"[FULL-RECON][SYSCTL] sysctlbyname: %s", name);
    return %orig;
}

%hookf(int, ptrace, int request, pid_t pid, caddr_t addr, int data) {
    NSLog(@"[FULL-RECON][PROC] ptrace request=%d pid=%d", request, pid);
    return %orig;
}

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    NSLog(@"[FULL-RECON][PROC] csops pid=%d ops=%u", pid, ops);
    return %orig;
}

%hookf(int, proc_pidinfo, int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    NSLog(@"[FULL-RECON][PROC] proc_pidinfo pid=%d flavor=%d", pid, flavor);
    return %orig;
}

%hookf(int, proc_listpids, uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    NSLog(@"[FULL-RECON][PROC] proc_listpids type=%u", type);
    return %orig;
}

%hookf(int, fork, void) {
    NSLog(@"[FULL-RECON][PROC] fork called!");
    return %orig;
}

%hookf(int, posix_spawn, pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if (path) NSLog(@"[FULL-RECON][PROC] posix_spawn: %s", path);
    return %orig;
}

// ==========================================
// SECTION 3: DYNAMIC LINKING
// ==========================================

%hookf(void *, dlopen, const char *path, int mode) {
    if (path) NSLog(@"[FULL-RECON][DYLD] dlopen: %s", path);
    return %orig;
}

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if (symbol) {
        if (strstr(symbol, "MSHook") || strstr(symbol, "substrate") ||
            strstr(symbol, "ellekit") || strstr(symbol, "roothide") ||
            strstr(symbol, "fishhook") || strstr(symbol, "Frida") ||
            strstr(symbol, "Cydia") || strstr(symbol, "hook")) {
            NSLog(@"[FULL-RECON][DYLD] dlsym (SUSPICIOUS): %s", symbol);
        }
    }
    return %orig;
}

%hookf(int, dladdr, const void *addr, Dl_info *info) {
    return %orig;
}

%hookf(uint32_t, _dyld_image_count, void) {
    uint32_t count = %orig;
    NSLog(@"[FULL-RECON][DYLD] _dyld_image_count = %u", count);
    return count;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *name = %orig;
    if (name) {
        if (strstr(name, ".jbroot") || strstr(name, "TweakInject") ||
            strstr(name, "roothide") || strstr(name, "ellekit") ||
            strstr(name, "Choicy") || strstr(name, "NSLogViewer") ||
            strstr(name, "Shadow") || strstr(name, "shadow")) {
            NSLog(@"[FULL-RECON][DYLD] image[%u] = %s", image_index, name);
        }
    }
    return name;
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    return %orig;
}

// ==========================================
// SECTION 4: OBJECTIVE-C RUNTIME
// ==========================================

%hookf(int, objc_getClassList, Class *buffer, int bufferCount) {
    NSLog(@"[FULL-RECON][OBJC] objc_getClassList bufferCount=%d", bufferCount);
    return %orig;
}

%hookf(Class, objc_getClass, const char *name) {
    if (name) {
        if (strstr(name, "Shadow") || strstr(name, "Choicy") ||
            strstr(name, "LCProtection") || strstr(name, "AutoPick") ||
            strstr(name, "Tweak") || strstr(name, "Hook")) {
            NSLog(@"[FULL-RECON][OBJC] objc_getClass (SUSPICIOUS): %s", name);
        }
    }
    return %orig;
}

%hookf(Class, objc_lookUpClass, const char *name) {
    if (name) {
        if (strstr(name, "Shadow") || strstr(name, "Choicy") ||
            strstr(name, "LCProtection") || strstr(name, "AutoPick")) {
            NSLog(@"[FULL-RECON][OBJC] objc_lookUpClass (SUSPICIOUS): %s", name);
        }
    }
    return %orig;
}

// ==========================================
// SECTION 5: MACH & KERNEL
// ==========================================

%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    NSLog(@"[FULL-RECON][MACH] task_info flavor=%u", flavor);
    return %orig;
}

%hookf(kern_return_t, mach_vm_region, vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    NSLog(@"[FULL-RECON][MACH] mach_vm_region (memory scan)");
    return %orig;
}

%hookf(kern_return_t, mach_vm_region_recurse, vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    NSLog(@"[FULL-RECON][MACH] mach_vm_region_recurse");
    return %orig;
}

%hookf(kern_return_t, task_get_special_port, task_t task, int which_port, mach_port_t *special_port) {
    NSLog(@"[FULL-RECON][MACH] task_get_special_port which=%d", which_port);
    return %orig;
}

// ==========================================
// SECTION 6: ENVIRONMENT VARIABLES
// ==========================================

%hookf(char *, getenv, const char *name) {
    if (name) {
        NSLog(@"[FULL-RECON][ENV] getenv: %s", name);
    }
    return %orig;
}

// ==========================================
// SECTION 7: KEYCHAIN
// ==========================================

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    NSDictionary *dict = (__bridge NSDictionary *)query;
    NSLog(@"[FULL-RECON][KEYCHAIN] SecItemCopyMatching: %@", dict);
    return %orig;
}

%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    NSDictionary *dict = (__bridge NSDictionary *)attributes;
    NSLog(@"[FULL-RECON][KEYCHAIN] SecItemAdd: %@", dict);
    return %orig;
}

// ==========================================
// SECTION 8: NSFileManager
// ==========================================

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path) NSLog(@"[FULL-RECON][NSFM] fileExistsAtPath: %@", path);
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path) NSLog(@"[FULL-RECON][NSFM] fileExistsAtPath:isDirectory: %@", path);
    return %orig;
}
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (path) NSLog(@"[FULL-RECON][NSFM] attributesOfItemAtPath: %@", path);
    return %orig;
}
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path) NSLog(@"[FULL-RECON][NSFM] contentsOfDirectoryAtPath: %@", path);
    return %orig;
}
- (NSData *)contentsAtPath:(NSString *)path {
    if (path) NSLog(@"[FULL-RECON][NSFM] contentsAtPath: %@", path);
    return %orig;
}
%end

// ==========================================
// SECTION 9: NSData / NSString file APIs
// ==========================================

%hook NSData
+ (id)dataWithContentsOfFile:(NSString *)path {
    if (path) NSLog(@"[FULL-RECON][NSDATA] dataWithContentsOfFile: %@", path);
    return %orig;
}
+ (id)dataWithContentsOfFile:(NSString *)path options:(NSUInteger)mask error:(NSError **)errorPtr {
    if (path) NSLog(@"[FULL-RECON][NSDATA] dataWithContentsOfFile:options: %@", path);
    return %orig;
}
%end

%hook NSString
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (path) NSLog(@"[FULL-RECON][NSSTRING] writeToFile: %@", path);
    return %orig;
}
%end

// ==========================================
// SECTION 10: UIApplication URL schemes
// ==========================================

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (url) NSLog(@"[FULL-RECON][UIAPP] canOpenURL: %@", url.absoluteString);
    return %orig;
}
- (void)openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenExternalURLOptionsKey, id> *)options completionHandler:(void (^)(BOOL))completion {
    if (url) NSLog(@"[FULL-RECON][UIAPP] openURL: %@", url.absoluteString);
    %orig;
}
%end

// ==========================================
// SECTION 11: NSURLSession
// ==========================================

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    NSString *url = request.URL.absoluteString;
    NSLog(@"[FULL-RECON][NET] %@ %@", request.HTTPMethod, url);
    return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    NSString *url = request.URL.absoluteString;
    NSLog(@"[FULL-RECON][NET] dataTask (no handler) %@ %@", request.HTTPMethod, url);
    return %orig;
}
%end
