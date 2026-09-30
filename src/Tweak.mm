#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libgen.h>
#import <string.h>
#include "offsets.h"

typedef void (*MSHookFunction_t)(void *symbol, void *hook, void **old);
static MSHookFunction_t MSHookFunction_p = NULL;

static uintptr_t g_base = 0;
static char g_image[256] = {0};

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

static BOOL DetectGame(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        if (strstr(path, "/Frameworks/") || strstr(path, "/System/") ||
            strstr(path, "/usr/") || strstr(path, "/private/preboot/") ||
            strstr(path, "LiveContainer") || strstr(path, "SideStore") ||
            strstr(path, "/Tweaks/")) continue;
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        if (hdr->filetype != MH_EXECUTE) continue;
        g_base = (uintptr_t)hdr;
        strncpy(g_image, basename((char *)path), sizeof(g_image) - 1);
        NRLog("image=%s base=%p", g_image, (void*)g_base);
        return YES;
    }
    return NO;
}

static inline void *GV(uint64_t rva) { return (void *)(g_base + rva); }

#pragma mark - ReceiveMessage

typedef void (*fn_recv_t)(void *self, void *msg, void *a, void *b, void *c, void *d);
static fn_recv_t orig_recv = NULL;

static void hook_recv(void *self, void *msg, void *a, void *b, void *c, void *d) {
    static __thread int guard = 0;
    if (!guard) {
        guard = 1;
        uint32_t msgId = 0;
        if (msg) memcpy(&msgId, msg, 4);
        NRLog("recv self=%p msg=%p id=0x%x", self, msg, msgId);
        guard = 0;
    }
    if (orig_recv) orig_recv(self, msg, a, b, c, d);
}

#pragma mark - GameButton ctor

typedef void *(*fn_gbCtor_t)(void *self, void *clip);
static fn_gbCtor_t orig_gbCtor = NULL;

static void *hook_gbCtor(void *self, void *clip) {
    void *r = orig_gbCtor ? orig_gbCtor(self, clip) : self;
    NRLog("GameButton self=%p clip=%p", self, clip);
    return r;
}

#pragma mark - Character ctor

typedef void *(*fn_charCtor_t)(void *self, void *a2, void *a3, void *a4);
static fn_charCtor_t orig_charCtor = NULL;

static void *hook_charCtor(void *self, void *a2, void *a3, void *a4) {
    void *r = orig_charCtor ? orig_charCtor(self, a2, a3, a4) : self;
    NRLog("Character self=%p", self);
    return r;
}

#pragma mark - HomePage ctor

typedef void *(*fn_homeCtor_t)(void *self, void *a2);
static fn_homeCtor_t orig_homeCtor = NULL;

static void *hook_homeCtor(void *self, void *a2) {
    void *r = orig_homeCtor ? orig_homeCtor(self, a2) : self;
    NRLog("HomePage self=%p", self);
    return r;
}

#pragma mark - MovieClip ctor

typedef void *(*fn_mcCtor_t)(void *self, void *a2);
static fn_mcCtor_t orig_mcCtor = NULL;

static void *hook_mcCtor(void *self, void *a2) {
    void *r = orig_mcCtor ? orig_mcCtor(self, a2) : self;
    NRLog("MovieClip self=%p", self);
    return r;
}

#pragma mark - NativeFont ctor

typedef void *(*fn_fontCtor_t)(void *self, void *a2);
static fn_fontCtor_t orig_fontCtor = NULL;

static void *hook_fontCtor(void *self, void *a2) {
    void *r = orig_fontCtor ? orig_fontCtor(self, a2) : self;
    NRLog("NativeFont self=%p", self);
    return r;
}

#pragma mark - Stage ctor

typedef void *(*fn_stageCtor_t)(void *self, void *a2);
static fn_stageCtor_t orig_stageCtor = NULL;

static void *hook_stageCtor(void *self, void *a2) {
    void *r = orig_stageCtor ? orig_stageCtor(self, a2) : self;
    NRLog("Stage self=%p", self);
    return r;
}

#pragma mark - Stage::setViewport

typedef void (*fn_setVP_t)(void *self, void *a2, void *a3, void *a4);
static fn_setVP_t orig_setVP = NULL;

static void hook_setVP(void *self, void *a2, void *a3, void *a4) {
    static BOOL once = NO;
    if (!once) { once = YES; NRLog("Stage::setViewport self=%p", self); }
    if (orig_setVP) orig_setVP(self, a2, a3, a4);
}

#pragma mark - LogicDataTables ctor

typedef void *(*fn_ldtCtor_t)(void *self, void *a2);
static fn_ldtCtor_t orig_ldtCtor = NULL;

static void *hook_ldtCtor(void *self, void *a2) {
    void *r = orig_ldtCtor ? orig_ldtCtor(self, a2) : self;
    NRLog("LogicDataTables self=%p", self);
    return r;
}

#pragma mark - LogicDataTables::initDataTable

typedef void (*fn_ldtInit_t)(void *self, int idx, void *a3);
static fn_ldtInit_t orig_ldtInit = NULL;

static void hook_ldtInit(void *self, int idx, void *a3) {
    NRLog("initDataTable self=%p idx=%d", self, idx);
    if (orig_ldtInit) orig_ldtInit(self, idx, a3);
}

#pragma mark - LogicProjectileData ctor

typedef void *(*fn_projCtor_t)(void *self, void *a2);
static fn_projCtor_t orig_projCtor = NULL;

static void *hook_projCtor(void *self, void *a2) {
    void *r = orig_projCtor ? orig_projCtor(self, a2) : self;
    NRLog("LogicProjectileData self=%p", self);
    return r;
}

#pragma mark - LogicProjectileData::getIntValueFromColumn

typedef int (*fn_projGetInt_t)(void *self, int col, int def);
static fn_projGetInt_t orig_projGetInt = NULL;

static int hook_projGetInt(void *self, int col, int def) {
    int v = orig_projGetInt ? orig_projGetInt(self, col, def) : def;
    static int logged = 0;
    if (logged < 200) { logged++; NRLog("projGetInt self=%p col=%d -> %d", self, col, v); }
    return v;
}

#pragma mark - MessageManager ctor

typedef void *(*fn_mmCtor_t)(void *self, void *a2);
static fn_mmCtor_t orig_mmCtor = NULL;

static void *hook_mmCtor(void *self, void *a2) {
    void *r = orig_mmCtor ? orig_mmCtor(self, a2) : self;
    NRLog("MessageManager self=%p", self);
    return r;
}

#pragma mark - NativeFont::formatString

typedef void *(*fn_fmt_t)(void *self, void *out, void *fmt);
static fn_fmt_t orig_fmt = NULL;

static void *hook_fmt(void *self, void *out, void *fmt) {
    static int logged = 0;
    if (logged < 50) { logged++; NRLog("formatString self=%p out=%p fmt=%p", self, out, fmt); }
    if (orig_fmt) return orig_fmt(self, out, fmt);
    return out;
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
    t.text = @"NullRythm";
    t.textColor = [UIColor systemYellowColor];
    t.font = [UIFont boldSystemFontOfSize:17];
    [self.stack addArrangedSubview:t];

    UILabel *i1 = [UILabel new];
    i1.text = [NSString stringWithFormat:@"image: %s", g_image];
    i1.textColor = [UIColor whiteColor];
    i1.font = [UIFont systemFontOfSize:11];
    i1.numberOfLines = 0;
    [self.stack addArrangedSubview:i1];

    UILabel *i2 = [UILabel new];
    i2.text = [NSString stringWithFormat:@"base: 0x%lx", g_base];
    i2.textColor = [UIColor whiteColor];
    i2.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    [self.stack addArrangedSubview:i2];

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
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        g_win = [[UIWindow alloc] initWithWindowScene:scene];
        g_win.windowLevel = UIWindowLevelAlert + 100;
        g_win.backgroundColor = [UIColor clearColor];
        g_win.rootViewController = [NRMenuVC new];
        g_win.frame = CGRectMake(70, 120, 290, 260);
        g_win.hidden = NO;
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_win action:@selector(nr_drag:)];
        [g_win addGestureRecognizer:pan];
    });
}

#pragma mark - Install

static void InstallHooks(void) {
    MSHookFunction_p = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!MSHookFunction_p) { NRLog("MSHookFunction missing"); return; }

    MSHookFunction_p(GV(RVA_MESSAGEMANAGER_RECEIVEMESSAGE), (void *)hook_recv, (void **)&orig_recv);
    MSHookFunction_p(GV(RVA_MESSAGEMANAGER_CTOR),          (void *)hook_mmCtor, (void **)&orig_mmCtor);
    MSHookFunction_p(GV(RVA_GAMEBUTTON_CTOR),              (void *)hook_gbCtor, (void **)&orig_gbCtor);
    MSHookFunction_p(GV(RVA_HOMEPAGE_CTOR),                (void *)hook_homeCtor, (void **)&orig_homeCtor);
    MSHookFunction_p(GV(RVA_CHARACTER_CTOR),               (void *)hook_charCtor, (void **)&orig_charCtor);
    MSHookFunction_p(GV(RVA_MOVIECLIP_CTOR),               (void *)hook_mcCtor, (void **)&orig_mcCtor);
    MSHookFunction_p(GV(RVA_NATIVEFONT_CTOR),              (void *)hook_fontCtor, (void **)&orig_fontCtor);
    MSHookFunction_p(GV(RVA_NATIVEFONT_FORMATSTRING),      (void *)hook_fmt, (void **)&orig_fmt);
    MSHookFunction_p(GV(RVA_STAGE_CTOR),                   (void *)hook_stageCtor, (void **)&orig_stageCtor);
    MSHookFunction_p(GV(RVA_STAGE_SETVIEWPORT),            (void *)hook_setVP, (void **)&orig_setVP);
    MSHookFunction_p(GV(RVA_LOGICDATATABLES_CTOR),         (void *)hook_ldtCtor, (void **)&orig_ldtCtor);
    MSHookFunction_p(GV(RVA_LOGICDATATABLES_INITDATATABLE),(void *)hook_ldtInit, (void **)&orig_ldtInit);
    MSHookFunction_p(GV(RVA_LOGICPROJECTILEDATA_CTOR),     (void *)hook_projCtor, (void **)&orig_projCtor);
    MSHookFunction_p(GV(RVA_LOGICPROJECTILEDATA_GETINTVALUE),(void *)hook_projGetInt, (void **)&orig_projGetInt);

    NRLog("all hooks installed");
}

__attribute__((constructor))
static void nr_init(void) {
    NRLog("=== NullRythm init ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!DetectGame()) { NRLog("game not found"); return; }
        InstallHooks();
        ShowMenu();
        NRLog("=== done ===");
    });
}