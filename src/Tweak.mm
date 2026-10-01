#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libgen.h>
#import <string.h>
#import <stdarg.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/time.h>
#import "offsets.h"

typedef kern_return_t (*MSHookFunction_t)(void *sym, void *hook, void **old);
typedef kern_return_t (*litehook_hook_function_t)(void *source, void *target);
typedef int (*DobbyHook_t)(void *address, void *replace, void **result);

static MSHookFunction_t p_MSHookFunction = NULL;
static litehook_hook_function_t p_litehook_hook = NULL;
static DobbyHook_t p_DobbyHook = NULL;

static FILE *g_log = NULL;
static NSLock *g_lock = nil;

static NSString *LogPath(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs withIntermediateDirectories:YES attributes:nil error:nil];
    return [docs stringByAppendingPathComponent:@"HookTest.log"];
}

static void TLog(NSString *msg) {
    if (!g_log) {
        g_lock = [NSLock new];
        g_log = fopen(LogPath().UTF8String, "a");
        if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);
    }
    if (!g_log) return;
    [g_lock lock];
    fprintf(g_log, "%s\n", msg.UTF8String);
    fflush(g_log);
    [g_lock unlock];
}

#define LOG(fmt, ...) TLog([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static uintptr_t g_base = 0;

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
        LOG(@"game base=%p", (void *)g_base);
        return YES;
    }
    LOG(@"game not found");
    return NO;
}

static int g_hook_count = 0;

static void *g_orig_recv_ms = NULL;
static void hook_recv_ms(void *self, void *msg, void *a, void *b, void *c, void *d) {
    g_hook_count++;
    if (g_hook_count < 5) LOG(@"MS/Dobby hook called #%d", g_hook_count);
    if (g_orig_recv_ms) ((void(*)(void*,void*,void*,void*,void*,void*))g_orig_recv_ms)(self, msg, a, b, c, d);
}

static void hook_recv_lite(void *self, void *msg, void *a, void *b, void *c, void *d) {
    g_hook_count++;
    if (g_hook_count < 5) LOG(@"litehook hook called #%d", g_hook_count);
}

static void LoadHookers(void) {
    LOG(@"=== loading hookers ===");

    p_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (p_MSHookFunction) {
        Dl_info info = {0};
        if (dladdr((void *)p_MSHookFunction, &info) && info.dli_fname) {
            LOG(@"MSHookFunction from: %s", info.dli_fname);
        } else {
            LOG(@"MSHookFunction = %p", p_MSHookFunction);
        }
    } else {
        LOG(@"MSHookFunction not found");
    }

    p_litehook_hook = (litehook_hook_function_t)dlsym(RTLD_DEFAULT, "litehook_hook_function");
    LOG(@"litehook_hook_function = %p", p_litehook_hook);

    p_DobbyHook = (DobbyHook_t)dlsym(RTLD_DEFAULT, "DobbyHook");
    if (!p_DobbyHook) {
        void *h = dlopen("@rpath/Dobby.framework/Dobby", RTLD_NOW | RTLD_GLOBAL);
        if (!h) h = dlopen("/usr/lib/libdobby.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (h) p_DobbyHook = (DobbyHook_t)dlsym(h, "DobbyHook");
    }
    LOG(@"DobbyHook = %p", p_DobbyHook);
}

static void TestMSHookFunction(void) {
    if (!p_MSHookFunction) { LOG(@"[MSHookFunction] skip: not available"); return; }
    if (!DetectGame()) { LOG(@"[MSHookFunction] skip: game not found"); return; }

    void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
    LOG(@"[MSHookFunction] hooking at %p", addr);
    fflush(g_log);

    g_orig_recv_ms = NULL;
    kern_return_t kr = p_MSHookFunction(addr, (void *)hook_recv_ms, &g_orig_recv_ms);
    LOG(@"[MSHookFunction] kr=%d orig=%p", kr, g_orig_recv_ms);
    if (g_orig_recv_ms) {
        LOG(@"[MSHookFunction] SUCCESS");
    } else {
        LOG(@"[MSHookFunction] FAIL: original is NULL");
    }
}

static void TestLitehookHook(void) {
    if (!p_litehook_hook) { LOG(@"[litehook_hook] skip: not available"); return; }
    if (!DetectGame()) { LOG(@"[litehook_hook] skip: game not found"); return; }

    void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
    LOG(@"[litehook_hook] hooking at %p", addr);
    fflush(g_log);

    kern_return_t kr = p_litehook_hook(addr, (void *)hook_recv_lite);
    LOG(@"[litehook_hook] kr=%d", kr);
    if (kr == 0) {
        LOG(@"[litehook_hook] HOOK INSTALLED (no original call)");
    } else {
        LOG(@"[litehook_hook] FAILED");
    }
}

static void TestDobby(void) {
    if (!p_DobbyHook) { LOG(@"[Dobby] skip: not available"); return; }
    if (!DetectGame()) { LOG(@"[Dobby] skip: game not found"); return; }

    void *addr = (void *)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
    LOG(@"[Dobby] hooking at %p", addr);
    fflush(g_log);

    void *orig = NULL;
    int r = p_DobbyHook(addr, (void *)hook_recv_ms, &orig);
    LOG(@"[Dobby] result=%d orig=%p", r, orig);
    if (orig) {
        LOG(@"[Dobby] SUCCESS");
    } else {
        LOG(@"[Dobby] FAIL: original is NULL");
    }
}

@interface NRVC : UIViewController
@property (nonatomic, strong) UILabel *info;
@end

@implementation NRVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
    self.view.layer.cornerRadius = 14;
    self.view.clipsToBounds = YES;

    UILabel *t = [UILabel new];
    t.text = @"Hook Methods Test";
    t.textColor = [UIColor systemYellowColor];
    t.font = [UIFont boldSystemFontOfSize:16];
    t.frame = CGRectMake(16, 14, 280, 22);
    [self.view addSubview:t];

    self.info = [UILabel new];
    self.info.textColor = [UIColor whiteColor];
    self.info.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    self.info.numberOfLines = 0;
    self.info.frame = CGRectMake(16, 44, 280, 220);
    [self.view addSubview:self.info];

    [self refresh];
    [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *tm){
        [self refresh];
    }];
}

- (void)refresh {
    self.info.text = [NSString stringWithFormat:
        @"MSHookFunction: %p\n"
        @"litehook_hook: %p\n"
        @"DobbyHook: %p\n\n"
        @"orig_recv: %p\n"
        @"hook calls: %d",
        p_MSHookFunction,
        p_litehook_hook,
        p_DobbyHook,
        g_orig_recv_ms,
        g_hook_count];
}
@end

static UIWindow *g_win = nil;

@interface UIWindow (NRDrag)
@end
@implementation UIWindow (NRDrag)
- (void)nr_drag:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self];
    CGRect f = self.frame;
    f.origin.x += t.x; f.origin.y += t.y;
    self.frame = f;
    [g setTranslation:CGPointZero inView:self];
}
@end

static void ShowUI(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        g_win = [[UIWindow alloc] initWithWindowScene:scene];
        g_win.windowLevel = UIWindowLevelAlert + 100;
        g_win.backgroundColor = [UIColor clearColor];
        g_win.rootViewController = [NRVC new];
        g_win.frame = CGRectMake(60, 100, 312, 300);
        g_win.hidden = NO;
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_win action:@selector(nr_drag:)];
        [g_win addGestureRecognizer:pan];
    });
}

__attribute__((constructor))
static void init(void) {
    LOG(@"=== Hook Test init ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        LoadHookers();
        TestMSHookFunction();
        TestLitehookHook();
        TestDobby();
        ShowUI();
        LOG(@"=== Hook Test done ===");
    });
}