// Tweak.mm
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libgen.h>
#import <string.h>
#import <stdarg.h>
#import <stdio.h>
#import <unistd.h>
#import "offsets.h"

typedef kern_return_t (*MSHookFunction_t)(void *sym, void *hook, void **old);
typedef kern_return_t (*litehook_hook_function_t)(void *source, void *target);
typedef int (*DobbyHook_t)(void *address, void *replace, void **result);
typedef int (*rebind_symbols_t)(struct rebinding rebindings[], size_t count);

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

static MSHookFunction_t p_MSHookFunction = NULL;
static litehook_hook_function_t p_litehook_hook = NULL;
static DobbyHook_t p_DobbyHook = NULL;
static rebind_symbols_t p_rebind_symbols = NULL;
static uintptr_t g_base = 0;
static void *g_orig_recv = NULL;
static int g_hook_count = 0;
static NSString *g_result = @"";

static void hook_recv(void *self, void *msg, void *a, void *b, void *c, void *d) {
    g_hook_count++;
    if (g_orig_recv) {
        ((void(*)(void*,void*,void*,void*,void*,void*))g_orig_recv)(self, msg, a, b, c, d);
    }
}

static BOOL DetectGame(void) {
    char execPath[PATH_MAX];
    uint32_t size = sizeof(execPath);
    if (_NSGetExecutablePath(execPath, &size) != 0) return NO;
    NSString *targetName = [[NSString stringWithUTF8String:execPath] lastPathComponent];
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        NSString *imageName = [[NSString stringWithUTF8String:path] lastPathComponent];
        if (![imageName isEqualToString:targetName]) continue;
        if (strstr(path, "LiveContainer") || strstr(path, "/System/")) continue;
        g_base = (uintptr_t)hdr;
        return YES;
    }
    return NO;
}

static void *FindElleKit(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        if (strcasestr(path, "ellekit")) {
            void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
            if (h) {
                void *f = dlsym(h, "MSHookFunction");
                if (f) return f;
            }
        }
    }
    const char *paths[] = {
        "/var/jb/usr/lib/ellekit/libellekit.dylib",
        "/usr/lib/ellekit/libellekit.dylib",
        "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/libellekit.dylib",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        void *h = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
        if (!h) continue;
        void *f = dlsym(h, "MSHookFunction");
        if (f) return f;
        dlclose(h);
    }
    return NULL;
}

static void RunAllTests(void) {
    NSMutableString *r = [NSMutableString new];
    [r appendString:@"=== Hook Methods Test ===\n\n"];

    // 1. ElleKit
    void *ellekit = FindElleKit();
    if (ellekit) {
        [r appendString:@"[ElleKit] found\n"];
        if (DetectGame()) {
            void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
            g_orig_recv = NULL;
            kern_return_t kr = ((MSHookFunction_t)ellekit)(addr, (void *)hook_recv, &g_orig_recv);
            if (g_orig_recv) {
                [r appendFormat:@"result: SUCCESS\nkr=%d orig=%p\n\n", kr, g_orig_recv];
            } else {
                [r appendFormat:@"result: FAILED (orig=NULL)\nkr=%d\n\n", kr];
            }
        } else {
            [r appendString:@"game not found\n\n"];
        }
    } else {
        [r appendString:@"[ElleKit] not found\n\n"];
    }

    // 2. CydiaSubstrate
    void *cydia = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (cydia) {
        Dl_info info = {0};
        if (dladdr(cydia, &info) && info.dli_fname) {
            [r appendFormat:@"[CydiaSubstrate]\npath: %s\n", basename((char*)info.dli_fname)];
        }
        if (DetectGame()) {
            void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
            g_orig_recv = NULL;
            kern_return_t kr = ((MSHookFunction_t)cydia)(addr, (void *)hook_recv, &g_orig_recv);
            if (g_orig_recv) {
                [r appendFormat:@"result: SUCCESS\nkr=%d orig=%p\n\n", kr, g_orig_recv];
            } else {
                [r appendFormat:@"result: FAILED (orig=NULL)\nkr=%d\n\n", kr];
            }
        } else {
            [r appendString:@"game not found\n\n"];
        }
    } else {
        [r appendString:@"[CydiaSubstrate] not found\n\n"];
    }

    // 3. litehook
    void *lh = dlsym(RTLD_DEFAULT, "litehook_hook_function");
    if (lh) {
        [r appendString:@"[litehook] found\n"];
        if (DetectGame()) {
            void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
            kern_return_t kr = ((litehook_hook_function_t)lh)(addr, (void *)hook_recv);
            [r appendFormat:@"result: kr=%d\n(original NOT callable)\n\n", kr];
        } else {
            [r appendString:@"game not found\n\n"];
        }
    } else {
        [r appendString:@"[litehook] not found\n\n"];
    }

    // 4. Dobby
    p_DobbyHook = (DobbyHook_t)dlsym(RTLD_DEFAULT, "DobbyHook");
    if (!p_DobbyHook) {
        void *h = dlopen("@rpath/Dobby.framework/Dobby", RTLD_NOW | RTLD_GLOBAL);
        if (!h) h = dlopen("/usr/lib/libdobby.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (h) p_DobbyHook = (DobbyHook_t)dlsym(h, "DobbyHook");
    }
    if (p_DobbyHook) {
        [r appendString:@"[Dobby] found\n"];
        if (DetectGame()) {
            void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
            void *orig = NULL;
            int res = p_DobbyHook(addr, (void *)hook_recv, &orig);
            if (orig) {
                [r appendFormat:@"result: SUCCESS\nret=%d orig=%p\n\n", res, orig];
            } else {
                [r appendFormat:@"result: FAILED (orig=NULL)\nret=%d\n\n", res];
            }
        } else {
            [r appendString:@"game not found\n\n"];
        }
    } else {
        [r appendString:@"[Dobby] not found\n\n"];
    }

    // 5. fishhook
    p_rebind_symbols = (rebind_symbols_t)dlsym(RTLD_DEFAULT, "rebind_symbols");
    if (p_rebind_symbols) {
        [r appendString:@"[fishhook] found\n"];
        [r appendString:@"result: only for imported symbols\n\n"];
    } else {
        [r appendString:@"[fishhook] not found\n\n"];
    }

    // 6. HookKit
    void *hk = dlopen("@rpath/HookKit.framework/HookKit", RTLD_NOW | RTLD_GLOBAL);
    if (!hk) hk = dlopen("/usr/lib/libHookKit.dylib", RTLD_NOW | RTLD_GLOBAL);
    if (hk) {
        void *sub = dlsym(hk, "HKSubstitutor");
        [r appendFormat:@"[HookKit] found: %p\n\n", sub];
    } else {
        [r appendString:@"[HookKit] not found\n\n"];
    }

    [r appendString:@"=== end ==="];
    g_result = r;
}

static void ShowAlert(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        UIViewController *root = scene.keyWindow.rootViewController;
        if (!root) return;

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"Hook Methods Test"
            message:g_result
            preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault handler:nil]];

        [root presentViewController:alert animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        RunAllTests();
        ShowAlert();
    });
}