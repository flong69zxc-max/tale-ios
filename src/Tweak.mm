#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <os/log.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libgen.h>
#import <stdarg.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/time.h>
#import "offsets.h"

typedef kern_return_t (*MSHookFunction_t)(void *sym, void *hook, void **old);
static MSHookFunction_t MSHookFunction_p = NULL;

static FILE *g_log = NULL;
static NSLock *g_lock = nil;
static char g_logPath[1024] = {0};
static char g_bundle[256] = {0};

#pragma mark - Logging core

static NSString *LogPath(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    return [docs stringByAppendingPathComponent:@"StosDebug.log"];
}

static NSString *Timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
    return [NSString stringWithUTF8String:buf];
}

static void OpenLog(void) {
    if (g_log) return;
    g_lock = [NSLock new];
    NSString *p = LogPath();
    strncpy(g_logPath, p.UTF8String, sizeof(g_logPath) - 1);
    g_log = fopen(g_logPath, "a");
    if (!g_log) return;
    setvbuf(g_log, NULL, _IOLBF, 0);
    int fd = fileno(g_log);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
}

static void TLog(NSString *msg) {
    if (!g_log) OpenLog();
    if (!g_log) return;
    [g_lock lock];
    fprintf(g_log, "[%s][%s] %s\n",
            Timestamp().UTF8String,
            g_bundle,
            msg.UTF8String);
    fflush(g_log);
    [g_lock unlock];
}

#define LOG(fmt, ...) TLog([NSString stringWithFormat:fmt, ##__VA_ARGS__])

#pragma mark - Diagnostics

static void DumpProcess(void) {
    LOG(@"=== log start ===");
    LOG(@"pid=%d", getpid());
    LOG(@"bundleID=%@", [NSBundle mainBundle].bundleIdentifier);
    LOG(@"execPath=%@", [NSBundle mainBundle].executablePath);
    LOG(@"home=%@", NSHomeDirectory());
    LOG(@"os=%@", [NSProcessInfo processInfo].operatingSystemVersionString);
    LOG(@"model=%@", [UIDevice currentDevice].model);
    LOG(@"system=%@ %@", [UIDevice currentDevice].systemName, [UIDevice currentDevice].systemVersion);
    LOG(@"physMem=%llu", [NSProcessInfo processInfo].physicalMemory);
    LOG(@"logPath=%s", g_logPath);
}

static void DumpEnv(void) {
    NSDictionary *env = [[NSProcessInfo processInfo] environment];
    LOG(@"=== env (%lu) ===", (unsigned long)env.count);
    for (NSString *k in env) LOG(@"  %@=%@", k, env[k]);
}

static void DumpDyld(void) {
    uint32_t n = _dyld_image_count();
    LOG(@"=== dyld images (%u) ===", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (!p) continue;
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        LOG(@"[%u] ft=%u %s", i, h ? h->filetype : 0, basename((char*)p));
    }
}

static void DumpHooker(void) {
    LOG(@"=== hooker symbols ===");
    const char *names[] = {
        "MSHookFunction", "MSHookMessageEx", "rebind_symbols",
        "DobbyHook", "DobbyCodePatch", "BreakJITWrite",
        "SubstrateHookFunction", "LCHookFunction",
        NULL
    };
    for (int i = 0; names[i]; i++) {
        void *p = dlsym(RTLD_DEFAULT, names[i]);
        if (!p) continue;
        Dl_info info = {0};
        if (dladdr(p, &info) && info.dli_fname) {
            LOG(@"  %-24s = %p  %s", names[i], p, basename((char*)info.dli_fname));
        } else {
            LOG(@"  %-24s = %p", names[i], p);
        }
    }
}

#pragma mark - StosDebug logger hooks

typedef void (*NSLog_t)(NSString *fmt, ...);
static NSLog_t orig_NSLog = NULL;
static void my_NSLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    TLog([NSString stringWithFormat:@"NSLog: %@", msg]);
    if (orig_NSLog) orig_NSLog(@"%@", msg);
}

typedef void (*os_log_impl_t)(void *dso, os_log_t log, os_log_type_t type, const char *format, uint8_t *buf, unsigned int size);
static os_log_impl_t orig_os_log_impl = NULL;
static void my_os_log_impl(void *dso, os_log_t log, os_log_type_t type, const char *format, uint8_t *buf, unsigned int size) {
    if (format) {
        const char *ts = "default";
        switch (type) {
            case OS_LOG_TYPE_INFO:  ts = "info";  break;
            case OS_LOG_TYPE_DEBUG: ts = "debug"; break;
            case OS_LOG_TYPE_ERROR: ts = "error"; break;
            case OS_LOG_TYPE_FAULT: ts = "fault"; break;
            default: break;
        }
        TLog([NSString stringWithFormat:@"os_log[%s]: %s", ts, format]);
    }
    if (orig_os_log_impl) orig_os_log_impl(dso, log, type, format, buf, size);
}

typedef void (*puts_t)(const char *);
static puts_t orig_puts = NULL;
static void my_puts(const char *s) {
    if (s) TLog([NSString stringWithFormat:@"puts: %s", s]);
    if (orig_puts) orig_puts(s);
}

static IMP g_orig_openURL_opt = NULL;
static IMP g_orig_scene_openURL = NULL;

static BOOL my_openURL(id self, SEL _cmd, UIApplication *app, NSURL *url, NSDictionary *opts) {
    LOG(@"[AppDelegate] openURL: %@ options: %@", url.absoluteString, opts);
    if (g_orig_openURL_opt)
        return ((BOOL(*)(id,SEL,UIApplication*,NSURL*,NSDictionary*))g_orig_openURL_opt)(self, _cmd, app, url, opts);
    return NO;
}

static void my_scene_openURL(id self, SEL _cmd, UIScene *scene, NSSet *ctxs) {
    LOG(@"[SceneDelegate] openURLContexts: %@", ctxs);
    if (g_orig_scene_openURL)
        ((void(*)(id,SEL,UIScene*,NSSet*))g_orig_scene_openURL)(self, _cmd, scene, ctxs);
}

static void InstallURLHooks(void) {
    Class appDel = objc_getClass("AppDelegate");
    if (appDel) {
        SEL s = sel_registerName("application:openURL:options:");
        Method m = class_getInstanceMethod(appDel, s);
        if (m) {
            g_orig_openURL_opt = method_getImplementation(m);
            method_setImplementation(m, (IMP)my_openURL);
            LOG(@"hooked AppDelegate openURL:options:");
        }
    }
    Class sceneDel = objc_getClass("SceneDelegate");
    if (sceneDel) {
        SEL s = sel_registerName("scene:openURLContexts:");
        Method m = class_getInstanceMethod(sceneDel, s);
        if (m) {
            g_orig_scene_openURL = method_getImplementation(m);
            method_setImplementation(m, (IMP)my_scene_openURL);
            LOG(@"hooked SceneDelegate scene:openURLContexts:");
        }
    }
}

static void InstallStosDebugHooks(void) {
    MSHookFunction_p = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    LOG(@"MSHookFunction=%p", MSHookFunction_p);
    if (MSHookFunction_p) {
        void *nslogSym = dlsym(RTLD_DEFAULT, "NSLog");
        if (nslogSym) {
            MSHookFunction_p(nslogSym, (void*)my_NSLog, (void**)&orig_NSLog);
            LOG(@"hooked NSLog orig=%p", orig_NSLog);
        }
        void *oslogSym = dlsym(RTLD_DEFAULT, "_os_log_impl");
        if (oslogSym) {
            MSHookFunction_p(oslogSym, (void*)my_os_log_impl, (void**)&orig_os_log_impl);
            LOG(@"hooked _os_log_impl orig=%p", orig_os_log_impl);
        }
        void *putsSym = dlsym(RTLD_DEFAULT, "puts");
        if (putsSym) {
            MSHookFunction_p(putsSym, (void*)my_puts, (void**)&orig_puts);
            LOG(@"hooked puts orig=%p", orig_puts);
        }
    }
    InstallURLHooks();
}

#pragma mark - JIT check (game process)

static uintptr_t g_gameBase = 0;
static BOOL g_jitOk = NO;
static void *g_orig_recv = NULL;
static int g_recvCount = 0;

static BOOL DetectGame(void) {
    char execPath[PATH_MAX];
    uint32_t size = sizeof(execPath);
    if (_NSGetExecutablePath(execPath, &size) != 0) return NO;
    NSString *targetName = [[NSString stringWithUTF8String:execPath] lastPathComponent];
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        NSString *imageName = [[NSString stringWithUTF8String:path] lastPathComponent];
        if (![imageName isEqualToString:targetName]) continue;
        if (strstr(path, "LiveContainer") || strstr(path, "/System/")) continue;
        g_gameBase = (uintptr_t)hdr;
        LOG(@"game base=%p", (void*)g_gameBase);
        return YES;
    }
    LOG(@"game not found");
    return NO;
}

static void hook_recv(void *self, void *msg, void *a, void *b, void *c, void *d) {
    g_recvCount++;
    if (g_recvCount < 10 || (g_recvCount % 100 == 0)) {
        uint32_t msgId = 0;
        if (msg) memcpy(&msgId, msg, 4);
        LOG(@"recv #%d self=%p msg=%p id=0x%x", g_recvCount, self, msg, msgId);
    }
    if (g_orig_recv)
        ((void(*)(void*,void*,void*,void*,void*,void*))g_orig_recv)(self, msg, a, b, c, d);
}

static void InstallJitCheck(void) {
    LOG(@"=== JIT check begin ===");
    MSHookFunction_p = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!MSHookFunction_p) {
        LOG(@"MSHookFunction missing");
        return;
    }
    LOG(@"MSHookFunction=%p", MSHookFunction_p);

    Dl_info info = {0};
    if (dladdr((void*)MSHookFunction_p, &info) && info.dli_fname) {
        LOG(@"hooker from: %s", info.dli_fname);
    }

    if (!DetectGame()) return;

    void *addr = (void*)(g_gameBase + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
    LOG(@"hooking recv at %p", addr);
    fflush(g_log);

    g_orig_recv = NULL;
    kern_return_t kr = MSHookFunction_p(addr, (void*)hook_recv, &g_orig_recv);
    LOG(@"kr=%d orig=%p", kr, g_orig_recv);

    g_jitOk = (g_orig_recv != NULL);
    LOG(@"JIT RESULT: %s", g_jitOk ? "YES" : "NO");
    LOG(@"=== JIT check done ===");
}

#pragma mark - UI for JIT status

@interface NRVC : UIViewController
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UILabel *info;
@end

@implementation NRVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.9];
    self.view.layer.cornerRadius = 14;
    self.view.clipsToBounds = YES;

    UILabel *t = [UILabel new];
    t.text = @"NullRythm JIT Test";
    t.textColor = [UIColor systemYellowColor];
    t.font = [UIFont boldSystemFontOfSize:16];
    t.frame = CGRectMake(16, 14, 280, 22);
    [self.view addSubview:t];

    self.status = [UILabel new];
    self.status.text = g_jitOk ? @"JIT: OK" : @"JIT: NOT AVAILABLE";
    self.status.textColor = g_jitOk ? [UIColor systemGreenColor] : [UIColor systemRedColor];
    self.status.font = [UIFont boldSystemFontOfSize:20];
    self.status.frame = CGRectMake(16, 46, 280, 26);
    [self.view addSubview:self.status];

    self.info = [UILabel new];
    self.info.textColor = [UIColor whiteColor];
    self.info.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.info.numberOfLines = 0;
    self.info.frame = CGRectMake(16, 84, 280, 110);
    [self.view addSubview:self.info];

    [self refresh];
    [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *tm){
        [self refresh];
    }];
}

- (void)refresh {
    self.info.text = [NSString stringWithFormat:
        @"MSHookFunction: %p\norig: %p\nrecv count: %d\nbundle: %s",
        MSHookFunction_p, g_orig_recv, g_recvCount, g_bundle];
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
            if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene*)s; break; }
        }
        if (!scene) return;
        g_win = [[UIWindow alloc] initWithWindowScene:scene];
        g_win.windowLevel = UIWindowLevelAlert + 100;
        g_win.backgroundColor = [UIColor clearColor];
        g_win.rootViewController = [NRVC new];
        g_win.frame = CGRectMake(60, 100, 312, 220);
        g_win.hidden = NO;
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_win action:@selector(nr_drag:)];
        [g_win addGestureRecognizer:pan];
    });
}

#pragma mark - Init

static void StartFlushTimer(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t){
            if (g_log) fflush(g_log);
        }];
    });
}

__attribute__((constructor))
static void sd_init(void) {
    OpenLog();

    NSString *bid = [NSBundle mainBundle].bundleIdentifier ?: @"";
    strncpy(g_bundle, bid.UTF8String, sizeof(g_bundle) - 1);

    DumpProcess();
    DumpEnv();
    DumpDyld();
    DumpHooker();

    BOOL isStos = [bid hasPrefix:@"com.stik.stikdebug"] ||
                  [bid hasPrefix:@"com.stossy11.StosDebug"];

    if (isStos) {
        LOG(@"mode: StosDebug logger");
        InstallStosDebugHooks();
    } else {
        LOG(@"mode: game JIT check");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            InstallJitCheck();
            ShowUI();
        });
    }

    StartFlushTimer();
    LOG(@"=== init done ===");
}