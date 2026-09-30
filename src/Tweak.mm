#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libgen.h>
#import <string.h>
#import <stdarg.h>
#import <mach/mach.h>
#import "offsets.h"

typedef kern_return_t (*MSHookFunction_t)(void *symbol, void *hook, void **old);
static MSHookFunction_t MSHookFunction_p = NULL;

static uintptr_t g_base = 0;
static char g_image[512] = {0};
static FILE *g_log = NULL;

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

static void *LoadHooker(void) {
    const char *paths[] = {
        "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/libellekit.dylib",
        "/var/jb/usr/lib/libhooker.dylib",
        "/usr/lib/libhooker.dylib",
        "/var/jb/usr/lib/libsubstrate.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/var/jb/usr/lib/libsubstitute.dylib",
        "/usr/lib/libsubstitute.dylib",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        void *h = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            void *f = dlsym(h, "MSHookFunction");
            if (f) {
                NRLog("hooker loaded from %s f=%p", paths[i], f);
                return f;
            }
            dlclose(h);
        }
    }
    void *f = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (f) {
        NRLog("hooker from RTLD_DEFAULT f=%p", f);
        return f;
    }
    NRLog("no hooker found");
    return NULL;
}

static BOOL DetectGame(void) {
    char execPath[PATH_MAX];
    uint32_t size = sizeof(execPath);
    if (_NSGetExecutablePath(execPath, &size) != 0) {
        NRLog("_NSGetExecutablePath failed");
        return NO;
    }
    NRLog("exec path: %s", execPath);

    NSString *targetName = [[NSString stringWithUTF8String:execPath] lastPathComponent];

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;

        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;

        NSString *imageName = [[NSString stringWithUTF8String:path] lastPathComponent];
        if (![imageName isEqualToString:targetName]) continue;

        if (strstr(path, "LiveContainer") || strstr(path, "SideStore") ||
            strstr(path, "/System/") || strstr(path, "/usr/")) continue;

        g_base = (uintptr_t)hdr;
        strncpy(g_image, path, sizeof(g_image) - 1);
        NRLog(">>> game: %s base=%p ft=%u", g_image, (void *)g_base, hdr->filetype);
        return YES;
    }

    NRLog("game not found: no image matches '%s'", targetName.UTF8String);
    return NO;
}

static inline void *GV(uint64_t rva) { return (void *)(g_base + rva); }

#pragma mark - Hooks

typedef void *(*fn_gbCtor_t)(void *self, void *clip);
static fn_gbCtor_t orig_gbCtor = NULL;
static int g_gbCount = 0;

static void *hook_gbCtor(void *self, void *clip) {
    g_gbCount++;
    NRLog("GameButton #%d self=%p clip=%p orig=%p", g_gbCount, self, clip, orig_gbCtor);
    if (orig_gbCtor) return orig_gbCtor(self, clip);
    return self;
}

typedef void *(*fn_charCtor_t)(void *self, void *a2, void *a3, void *a4);
static fn_charCtor_t orig_charCtor = NULL;
static int g_charCount = 0;

static void *hook_charCtor(void *self, void *a2, void *a3, void *a4) {
    g_charCount++;
    NRLog("Character #%d self=%p orig=%p", g_charCount, self, orig_charCtor);
    if (orig_charCtor) return orig_charCtor(self, a2, a3, a4);
    return self;
}

typedef void (*fn_setVP_t)(void *self, void *a2, void *a3, void *a4);
static fn_setVP_t orig_setVP = NULL;
static int g_vpCount = 0;

static void hook_setVP(void *self, void *a2, void *a3, void *a4) {
    g_vpCount++;
    if (g_vpCount < 10) NRLog("setViewport #%d self=%p orig=%p", g_vpCount, self, orig_setVP);
    if (orig_setVP) orig_setVP(self, a2, a3, a4);
}

#pragma mark - UI

@interface NRMenuVC : UIViewController
@property (nonatomic, strong) UIStackView *stack;
@property (nonatomic, strong) UIScrollView *scroll;
@end

@implementation NRMenuVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
    self.view.layer.cornerRadius = 12;
    self.view.clipsToBounds = YES;

    self.scroll = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    self.scroll.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:self.scroll];

    self.stack = [[UIStackView alloc] initWithFrame:CGRectMake(12, 12, 260, 100)];
    self.stack.axis = UILayoutConstraintAxisVertical;
    self.stack.spacing = 6;
    [self.scroll addSubview:self.stack];

    UILabel *t = [UILabel new];
    t.text = @"NullRythm Test";
    t.textColor = [UIColor systemYellowColor];
    t.font = [UIFont boldSystemFontOfSize:17];
    [self.stack addArrangedSubview:t];

    UILabel *i1 = [UILabel new];
    i1.text = [NSString stringWithFormat:@"image: %s", g_image];
    i1.textColor = [UIColor whiteColor];
    i1.font = [UIFont systemFontOfSize:10];
    i1.numberOfLines = 0;
    [self.stack addArrangedSubview:i1];

    UILabel *i2 = [UILabel new];
    i2.text = [NSString stringWithFormat:@"base: 0x%lx", g_base];
    i2.textColor = [UIColor whiteColor];
    i2.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    [self.stack addArrangedSubview:i2];

    UILabel *i3 = [UILabel new];
    i3.text = [NSString stringWithFormat:@"hooker: %p", MSHookFunction_p];
    i3.textColor = [UIColor whiteColor];
    i3.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    [self.stack addArrangedSubview:i3];

    UILabel *i4 = [UILabel new];
    i4.text = [NSString stringWithFormat:@"gb orig: %p", orig_gbCtor];
    i4.textColor = [UIColor whiteColor];
    i4.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    [self.stack addArrangedSubview:i4];

    UILabel *i5 = [UILabel new];
    i5.text = [NSString stringWithFormat:@"char orig: %p", orig_charCtor];
    i5.textColor = [UIColor whiteColor];
    i5.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    [self.stack addArrangedSubview:i5];

    UILabel *i6 = [UILabel new];
    i6.text = [NSString stringWithFormat:@"vp orig: %p", orig_setVP];
    i6.textColor = [UIColor whiteColor];
    i6.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    [self.stack addArrangedSubview:i6];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self.stack layoutIfNeeded];
        self.stack.frame = CGRectMake(12, 12, 260, self.stack.frame.size.height);
        self.scroll.contentSize = CGSizeMake(284, self.stack.frame.size.height + 24);
    });
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

static void ShowMenu(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindowScene *scene = nil;
            for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
                if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
            }
            if (!scene) { NRLog("ShowMenu: no scene"); return; }
            g_win = [[UIWindow alloc] initWithWindowScene:scene];
            g_win.windowLevel = UIWindowLevelAlert + 100;
            g_win.backgroundColor = [UIColor clearColor];
            g_win.rootViewController = [NRMenuVC new];
            g_win.frame = CGRectMake(70, 120, 290, 300);
            g_win.hidden = NO;
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_win action:@selector(nr_drag:)];
            [g_win addGestureRecognizer:pan];
            NRLog("ShowMenu: ok");
        } @catch (NSException *e) {
            NRLog("ShowMenu exception: %s", e.reason.UTF8String);
        }
    });
}

#pragma mark - Install

static void InstallOne(const char *name, uint64_t rva, void *hook, void **orig) {
    if (!MSHookFunction_p) {
        NRLog("skip %s: MSHookFunction missing", name);
        return;
    }
    void *addr = (void *)(g_base + rva);
    NRLog("installing %s rva=0x%llx addr=%p", name, rva, addr);
    fflush(g_log);
    *orig = NULL;
    kern_return_t kr = MSHookFunction_p(addr, hook, orig);
    NRLog("  -> %s kr=%d orig=%p", name, kr, orig ? *orig : NULL);
    fflush(g_log);
}

static void InstallHooks(void) {
    NRLog("=== InstallHooks begin ===");
    fflush(g_log);

    MSHookFunction_p = (MSHookFunction_t)LoadHooker();
    if (!MSHookFunction_p) {
        NRLog("MSHookFunction missing");
        return;
    }
    NRLog("MSHookFunction = %p", MSHookFunction_p);
    fflush(g_log);

    InstallOne("GameButton::ctor", RVA_GAMEBUTTON_CTOR, (void *)hook_gbCtor, (void **)&orig_gbCtor);
    InstallOne("Character::ctor", RVA_CHARACTER_CTOR, (void *)hook_charCtor, (void **)&orig_charCtor);
    InstallOne("Stage::setViewport", RVA_STAGE_SETVIEWPORT, (void *)hook_setVP, (void **)&orig_setVP);

    NRLog("=== InstallHooks done ===");
    fflush(g_log);
}

static void TryInstall(void);

static void ScheduleRetry(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ TryInstall(); });
}

static void TryInstall(void) {
    if (!DetectGame()) {
        NRLog("retry...");
        ScheduleRetry();
        return;
    }
    InstallHooks();
    NRLog("calling ShowMenu");
    fflush(g_log);
    ShowMenu();
    NRLog("=== done ===");
    fflush(g_log);
}

__attribute__((constructor))
static void nr_init(void) {
    NRLog("=== NullRythm init ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ TryInstall(); });
}