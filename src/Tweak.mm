#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <libgen.h>
#import <string.h>
#import <stdarg.h>
#import "offsets.h"

typedef kern_return_t (*MSHookFunction_t)(void *symbol, void *hook, void **old);
typedef void (*MSHookMessageEx_t)(Class cls, SEL sel, IMP hook, IMP *old);

static MSHookFunction_t MSHookFunction_p = NULL;
static MSHookMessageEx_t MSHookMessageEx_p = NULL;
static char g_hooker_path[512] = {0};

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

#pragma mark - Hooker loading (ElleKit preferred)

static BOOL TryLoadHooker(const char *path) {
    void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!h) return NO;

    void *fFn  = dlsym(h, "MSHookFunction");
    void *fMsg = dlsym(h, "MSHookMessageEx");
    if (!fFn || !fMsg) { dlclose(h); return NO; }

    Dl_info info = {0};
    if (dladdr(fFn, &info) && info.dli_fname) {
        strncpy(g_hooker_path, info.dli_fname, sizeof(g_hooker_path) - 1);
    }
    MSHookFunction_p  = (MSHookFunction_t)fFn;
    MSHookMessageEx_p = (MSHookMessageEx_t)fMsg;
    NRLog("hooker loaded: %s -> fn=%p msg=%p (%s)", path, fFn, fMsg, g_hooker_path);
    return YES;
}

static void LoadHooker(void) {
    const char *preferred[] = {
        "/var/jb/usr/lib/ellekit/libellekit.dylib",
        "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/libellekit.dylib",
        "/var/jb/usr/lib/libhooker.dylib",
        "/usr/lib/libhooker.dylib",
        NULL
    };
    for (int i = 0; preferred[i]; i++) {
        if (TryLoadHooker(preferred[i])) return;
    }

    void *f = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (f) {
        Dl_info info = {0};
        if (dladdr(f, &info) && info.dli_fname) {
            strncpy(g_hooker_path, info.dli_fname, sizeof(g_hooker_path) - 1);
            if (strstr(info.dli_fname, "CydiaSubstrate") ||
                strstr(info.dli_fname, "libsubstrate")) {
                NRLog("rejecting CydiaSubstrate: %s", info.dli_fname);
                MSHookFunction_p = NULL;
                return;
            }
        }
        MSHookFunction_p = (MSHookFunction_t)f;
        MSHookMessageEx_p = (MSHookMessageEx_t)dlsym(RTLD_DEFAULT, "MSHookMessageEx");
        NRLog("hooker from RTLD_DEFAULT fn=%p msg=%p (%s)", f, MSHookMessageEx_p, g_hooker_path);
    } else {
        NRLog("no hooker found");
    }
}

#pragma mark - Detect game

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
        strncpy(g_image, path, sizeof(g_image) - 1);
        NRLog(">>> game: %s base=%p", g_image, (void*)g_base);
        return YES;
    }
    NRLog("game not found");
    return NO;
}

static inline void *GV(uint64_t rva) { return (void *)(g_base + rva); }

#pragma mark - Hooks

typedef void (*fn_recv_t)(void *self, void *msg, void *a, void *b, void *c, void *d);
static fn_recv_t orig_recv = NULL;
static int g_recv_count = 0;

static void hook_recv(void *self, void *msg, void *a, void *b, void *c, void *d) {
    static __thread int guard = 0;
    if (!guard) {
        guard = 1;
        g_recv_count++;
        uint32_t msgId = 0;
        if (msg) memcpy(&msgId, msg, 4);
        if (g_recv_count < 50 || (g_recv_count % 100 == 0)) {
            NRLog("recv #%d self=%p msg=%p id=0x%x", g_recv_count, self, msg, msgId);
        }
        guard = 0;
    }
    if (orig_recv) orig_recv(self, msg, a, b, c, d);
}

typedef void *(*fn_mmCtor_t)(void *self, void *a2);
static fn_mmCtor_t orig_mmCtor = NULL;

static void *hook_mmCtor(void *self, void *a2) {
    NRLog("MessageManager self=%p", self);
    return orig_mmCtor ? orig_mmCtor(self, a2) : self;
}

typedef void *(*fn_gbCtor_t)(void *self, void *clip);
static fn_gbCtor_t orig_gbCtor = NULL;
static int g_gb_count = 0;

static void *hook_gbCtor(void *self, void *clip) {
    g_gb_count++;
    if (g_gb_count < 50 || (g_gb_count % 100 == 0)) {
        NRLog("GameButton #%d self=%p clip=%p", g_gb_count, self, clip);
    }
    return orig_gbCtor ? orig_gbCtor(self, clip) : self;
}

typedef void *(*fn_charCtor_t)(void *self, void *a2, void *a3, void *a4);
static fn_charCtor_t orig_charCtor = NULL;
static int g_char_count = 0;

static void *hook_charCtor(void *self, void *a2, void *a3, void *a4) {
    g_char_count++;
    if (g_char_count < 100 || (g_char_count % 100 == 0)) {
        NRLog("Character #%d self=%p", g_char_count, self);
    }
    return orig_charCtor ? orig_charCtor(self, a2, a3, a4) : self;
}

typedef void (*fn_setVP_t)(void *self, void *a2, void *a3, void *a4);
static fn_setVP_t orig_setVP = NULL;
static int g_vp_count = 0;

static void hook_setVP(void *self, void *a2, void *a3, void *a4) {
    g_vp_count++;
    if (g_vp_count < 10) NRLog("setViewport #%d self=%p", g_vp_count, self);
    if (orig_setVP) orig_setVP(self, a2, a3, a4);
}

typedef void *(*fn_homeCtor_t)(void *self, void *a2);
static fn_homeCtor_t orig_homeCtor = NULL;

static void *hook_homeCtor(void *self, void *a2) {
    NRLog("HomePage self=%p", self);
    return orig_homeCtor ? orig_homeCtor(self, a2) : self;
}

typedef void *(*fn_mcCtor_t)(void *self, void *a2);
static fn_mcCtor_t orig_mcCtor = NULL;

static void *hook_mcCtor(void *self, void *a2) {
    return orig_mcCtor ? orig_mcCtor(self, a2) : self;
}

typedef void *(*fn_fontCtor_t)(void *self, void *a2);
static fn_fontCtor_t orig_fontCtor = NULL;

static void *hook_fontCtor(void *self, void *a2) {
    return orig_fontCtor ? orig_fontCtor(self, a2) : self;
}

typedef void *(*fn_fmt_t)(void *self, void *out, void *fmt);
static fn_fmt_t orig_fmt = NULL;

static void *hook_fmt(void *self, void *out, void *fmt) {
    return orig_fmt ? orig_fmt(self, out, fmt) : out;
}

typedef void *(*fn_ldtCtor_t)(void *self, void *a2);
static fn_ldtCtor_t orig_ldtCtor = NULL;

static void *hook_ldtCtor(void *self, void *a2) {
    NRLog("LogicDataTables self=%p", self);
    return orig_ldtCtor ? orig_ldtCtor(self, a2) : self;
}

typedef void (*fn_ldtInit_t)(void *self, int idx, void *a3);
static fn_ldtInit_t orig_ldtInit = NULL;

static void hook_ldtInit(void *self, int idx, void *a3) {
    NRLog("initDataTable self=%p idx=%d", self, idx);
    if (orig_ldtInit) orig_ldtInit(self, idx, a3);
}

typedef void *(*fn_projCtor_t)(void *self, void *a2);
static fn_projCtor_t orig_projCtor = NULL;

static void *hook_projCtor(void *self, void *a2) {
    NRLog("LogicProjectileData self=%p", self);
    return orig_projCtor ? orig_projCtor(self, a2) : self;
}

typedef int (*fn_projGetInt_t)(void *self, int col, int def);
static fn_projGetInt_t orig_projGetInt = NULL;

static int hook_projGetInt(void *self, int col, int def) {
    int v = orig_projGetInt ? orig_projGetInt(self, col, def) : def;
    static int logged = 0;
    if (logged < 100) { logged++; NRLog("projGetInt self=%p col=%d -> %d", self, col, v); }
    return v;
}

#pragma mark - Install

static int g_hooks_ok = 0;
static int g_hooks_fail = 0;

static void InstallOne(const char *name, uint64_t rva, void *hook, void **orig) {
    if (!MSHookFunction_p) { NRLog("skip %s: no hooker", name); g_hooks_fail++; return; }
    void *addr = (void *)(g_base + rva);
    NRLog("installing %s rva=0x%llx addr=%p", name, rva, addr);
    fflush(g_log);
    *orig = NULL;
    kern_return_t kr = MSHookFunction_p(addr, hook, orig);
    NRLog("  -> %s kr=%d orig=%p", name, kr, orig ? *orig : NULL);
    fflush(g_log);
    if (orig && *orig) g_hooks_ok++; else g_hooks_fail++;
}

static void InstallHooks(void) {
    NRLog("=== InstallHooks begin ===");
    LoadHooker();
    if (!MSHookFunction_p) {
        NRLog("no hooker available");
        return;
    }

    InstallOne("MessageManager::receiveMessage", RVA_MESSAGEMANAGER_RECEIVEMESSAGE,
               (void*)hook_recv, (void**)&orig_recv);
    InstallOne("MessageManager::ctor", RVA_MESSAGEMANAGER_CTOR,
               (void*)hook_mmCtor, (void**)&orig_mmCtor);
    InstallOne("GameButton::ctor", RVA_GAMEBUTTON_CTOR,
               (void*)hook_gbCtor, (void**)&orig_gbCtor);
    InstallOne("Character::ctor", RVA_CHARACTER_CTOR,
               (void*)hook_charCtor, (void**)&orig_charCtor);
    InstallOne("Stage::setViewport", RVA_STAGE_SETVIEWPORT,
               (void*)hook_setVP, (void**)&orig_setVP);
    InstallOne("HomePage::ctor", RVA_HOMEPAGE_CTOR,
               (void*)hook_homeCtor, (void**)&orig_homeCtor);
    InstallOne("MovieClip::ctor", RVA_MOVIECLIP_CTOR,
               (void*)hook_mcCtor, (void**)&orig_mcCtor);
    InstallOne("NativeFont::ctor", RVA_NATIVEFONT_CTOR,
               (void*)hook_fontCtor, (void**)&orig_fontCtor);
    InstallOne("NativeFont::formatString", RVA_NATIVEFONT_FORMATSTRING,
               (void*)hook_fmt, (void**)&orig_fmt);
    InstallOne("LogicDataTables::ctor", RVA_LOGICDATATABLES_CTOR,
               (void*)hook_ldtCtor, (void**)&orig_ldtCtor);
    InstallOne("LogicDataTables::initDataTable", RVA_LOGICDATATABLES_INITDATATABLE,
               (void*)hook_ldtInit, (void**)&orig_ldtInit);
    InstallOne("LogicProjectileData::ctor", RVA_LOGICPROJECTILEDATA_CTOR,
               (void*)hook_projCtor, (void**)&orig_projCtor);
    InstallOne("LogicProjectileData::getIntValue", RVA_LOGICPROJECTILEDATA_GETINTVALUE,
               (void*)hook_projGetInt, (void**)&orig_projGetInt);

    NRLog("=== InstallHooks done ok=%d fail=%d ===", g_hooks_ok, g_hooks_fail);
    fflush(g_log);
}

#pragma mark - UI

@interface NRMenuVC : UIViewController
@property (nonatomic, strong) UIStackView *stack;
@property (nonatomic, strong) UIScrollView *scroll;
@end

@implementation NRMenuVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
    self.view.layer.cornerRadius = 12;
    self.view.clipsToBounds = YES;

    self.scroll = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    self.scroll.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:self.scroll];

    self.stack = [[UIStackView alloc] initWithFrame:CGRectMake(12, 12, 300, 100)];
    self.stack.axis = UILayoutConstraintAxisVertical;
    self.stack.spacing = 4;
    [self.scroll addSubview:self.stack];

    NSArray *lines = @[
        @"NullRythm",
        [NSString stringWithFormat:@"hooker: %s", g_hooker_path],
        [NSString stringWithFormat:@"MSHookFunction: %p", MSHookFunction_p],
        [NSString stringWithFormat:@"MSHookMessageEx: %p", MSHookMessageEx_p],
        [NSString stringWithFormat:@"hooks ok: %d / fail: %d", g_hooks_ok, g_hooks_fail],
        [NSString stringWithFormat:@"orig_recv: %p", orig_recv],
        [NSString stringWithFormat:@"orig_gb: %p", orig_gbCtor],
        [NSString stringWithFormat:@"orig_char: %p", orig_charCtor],
        [NSString stringWithFormat:@"recv count: %d", g_recv_count],
        [NSString stringWithFormat:@"gb count: %d", g_gb_count],
        [NSString stringWithFormat:@"char count: %d", g_char_count],
        @"",
        @"Log: Documents/NullRythm.log",
    ];
    for (NSString *line in lines) {
        UILabel *l = [UILabel new];
        l.text = line;
        BOOL isTitle = [line isEqualToString:@"NullRythm"];
        l.textColor = isTitle ? [UIColor systemYellowColor] : [UIColor whiteColor];
        l.font = isTitle ? [UIFont boldSystemFontOfSize:16]
                         : [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
        l.numberOfLines = 0;
        [self.stack addArrangedSubview:l];
    }

    [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t){
        UILabel *recvLbl = self.stack.arrangedSubviews[8];
        UILabel *gbLbl   = self.stack.arrangedSubviews[9];
        UILabel *chLbl   = self.stack.arrangedSubviews[10];
        recvLbl.text = [NSString stringWithFormat:@"recv count: %d", g_recv_count];
        gbLbl.text   = [NSString stringWithFormat:@"gb count: %d", g_gb_count];
        chLbl.text   = [NSString stringWithFormat:@"char count: %d", g_char_count];
    }];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self.stack layoutIfNeeded];
        self.stack.frame = CGRectMake(12, 12, 300, self.stack.frame.size.height);
        self.scroll.contentSize = CGSizeMake(324, self.stack.frame.size.height + 24);
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
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        g_win = [[UIWindow alloc] initWithWindowScene:scene];
        g_win.windowLevel = UIWindowLevelAlert + 100;
        g_win.backgroundColor = [UIColor clearColor];
        g_win.rootViewController = [NRMenuVC new];
        g_win.frame = CGRectMake(50, 100, 320, 420);
        g_win.hidden = NO;
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_win action:@selector(nr_drag:)];
        [g_win addGestureRecognizer:pan];
    });
}

#pragma mark - Init

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
    ShowMenu();
    NRLog("=== done ===");
}

__attribute__((constructor))
static void nr_init(void) {
    NRLog("=== NullRythm init ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ TryInstall(); });
}