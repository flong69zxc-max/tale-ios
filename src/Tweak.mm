#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libgen.h>
#import <string.h>
#import <stdarg.h>
#import "offsets.h"

typedef kern_return_t (*MSHookFunction_t)(void *sym, void *hook, void **old);
static MSHookFunction_t MSHookFunction_p = NULL;

static uintptr_t g_base = 0;
static FILE *g_log = NULL;
static BOOL g_jitOk = NO;
static char g_hookerPath[512] = {0};

static void NRLog(const char *fmt, ...) {
    if (!g_log) {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *p = [dir stringByAppendingPathComponent:@"NullRythm.log"];
        g_log = fopen(p.UTF8String, "a");
    }
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    fputc('\n', g_log);
    va_end(ap);
    fflush(g_log);
}

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
        g_base = (uintptr_t)hdr;
        NRLog("game base=%p", (void*)g_base);
        return YES;
    }
    return NO;
}

static void *g_orig_recv = NULL;
static int g_recv_count = 0;

static void hook_recv(void *self, void *msg, void *a, void *b, void *c, void *d) {
    g_recv_count++;
    if (g_recv_count < 10) {
        uint32_t msgId = 0;
        if (msg) memcpy(&msgId, msg, 4);
        NRLog("recv #%d self=%p msg=%p id=0x%x", g_recv_count, self, msg, msgId);
    }
    if (g_orig_recv) {
        ((void(*)(void*,void*,void*,void*,void*,void*))g_orig_recv)(self, msg, a, b, c, d);
    }
}

static void Install(void) {
    MSHookFunction_p = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    NRLog("MSHookFunction=%p", MSHookFunction_p);
    if (!MSHookFunction_p) return;

    Dl_info info = {0};
    if (dladdr((void*)MSHookFunction_p, &info) && info.dli_fname) {
        strncpy(g_hookerPath, info.dli_fname, sizeof(g_hookerPath)-1);
        NRLog("hooker from: %s", g_hookerPath);
    }

    if (!DetectGame()) { NRLog("game not found"); return; }

    void *addr = (void*)(g_base + RVA_MESSAGEMANAGER_RECEIVEMESSAGE);
    NRLog("hooking recv at %p", addr);
    fflush(g_log);

    g_orig_recv = NULL;
    kern_return_t kr = MSHookFunction_p(addr, (void*)hook_recv, &g_orig_recv);
    NRLog("kr=%d orig=%p", kr, g_orig_recv);

    g_jitOk = (g_orig_recv != NULL);
    NRLog("JIT RESULT: %s", g_jitOk ? "YES" : "NO");
}

@interface NRVC : UIViewController
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
    t.frame = CGRectMake(16, 16, 280, 22);
    [self.view addSubview:t];

    UILabel *status = [UILabel new];
    status.text = g_jitOk ? @"✅ JIT: OK" : @"❌ JIT: NOT AVAILABLE";
    status.textColor = g_jitOk ? [UIColor systemGreenColor] : [UIColor systemRedColor];
    status.font = [UIFont boldSystemFontOfSize:20];
    status.frame = CGRectMake(16, 50, 280, 26);
    [self.view addSubview:status];

    UILabel *info = [UILabel new];
    info.text = [NSString stringWithFormat:
        @"hooker: %s\nMSHookFunction: %p\norig: %p\nrecv count: %d",
        g_hookerPath[0] ? basename(g_hookerPath) : "?",
        MSHookFunction_p,
        g_orig_recv,
        g_recv_count];
    info.textColor = [UIColor whiteColor];
    info.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    info.numberOfLines = 0;
    info.frame = CGRectMake(16, 90, 280, 110);
    [self.view addSubview:info];

    [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *tm){
        info.text = [NSString stringWithFormat:
            @"hooker: %s\nMSHookFunction: %p\norig: %p\nrecv count: %d",
            g_hookerPath[0] ? basename(g_hookerPath) : "?",
            MSHookFunction_p,
            g_orig_recv,
            g_recv_count];
    }];
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

__attribute__((constructor))
static void nr_init(void) {
    NRLog("=== JIT test init ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        Install();
        ShowUI();
    });
}