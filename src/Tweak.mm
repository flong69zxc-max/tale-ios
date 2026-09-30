#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <libgen.h>
#import <string.h>
#import <stdarg.h>
#import "offsets.h"

static FILE *g_log = NULL;
static uintptr_t g_base = 0;
static char g_image[512] = {0};

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

static void DumpEnvironment(void) {
    NRLog("--- env ---");
    NRLog("pid=%d", getpid());
    NRLog("NSHomeDirectory=%s", NSHomeDirectory().UTF8String);
    NRLog("bundleID=%s", [NSBundle mainBundle].bundleIdentifier.UTF8String);
    NRLog("execPath=%s", [NSBundle mainBundle].executablePath.UTF8String);
    NSProcessInfo *pi = [NSProcessInfo processInfo];
    NRLog("osVersion=%s", pi.operatingSystemVersionString.UTF8String);
    NRLog("physicalMemory=%llu", pi.physicalMemory);
    NRLog("processorCount=%lu", (unsigned long)pi.processorCount);
    NRLog("isJailbroken=%d", [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"] ? 1 : 0);
}

static void DumpDyldImages(void) {
    uint32_t n = _dyld_image_count();
    NRLog("--- dyld images (%u) ---", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *path = _dyld_get_image_name(i);
        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!path || !hdr) continue;
        const char *bn = basename((char *)path);
        NRLog("[%u] ft=%u base=%p name=%s",
              i, hdr->filetype, (void *)hdr, bn);
    }
}

static void DumpHooker(void) {
    NRLog("--- hooker symbols ---");
    const char *names[] = {
        "MSHookFunction",
        "MSHookMessageEx",
        "rebind_symbols",
        "rebind_symbols_image",
        "fishhook_remap",
        "LCHookFunction",
        "LCFindSymbol",
        "SubstrateHookFunction",
        "SubstrateHookFunctionRet",
        "SubstituteHookFunction",
        "hook_function",
        NULL
    };
    for (int i = 0; names[i]; i++) {
        void *p = dlsym(RTLD_DEFAULT, names[i]);
        if (p) {
            Dl_info info = {0};
            if (dladdr(p, &info)) {
                NRLog("%-24s = %p  %s  (%s)",
                      names[i], p,
                      info.dli_fname ? basename((char*)info.dli_fname) : "?",
                      info.dli_sname ? info.dli_sname : "?");
            } else {
                NRLog("%-24s = %p  (dladdr failed)", names[i], p);
            }
        }
    }
}

static void DumpObjcClasses(void) {
    NRLog("--- objc classes of interest ---");
    const char *targets[] = {
        "BattleScreen",
        "BattleMode",
        "LogicBattleModeClient",
        "LogicGameObjectClient",
        "GameButton",
        "Character",
        "Stage",
        "MovieClip",
        "NativeFont",
        "MessageManager",
        NULL
    };
    for (int i = 0; targets[i]; i++) {
        Class c = objc_getClass(targets[i]);
        if (!c) continue;
        NRLog("class %s = %p", targets[i], (__bridge void *)c);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(c, &count);
        if (methods) {
            for (unsigned int j = 0; j < count && j < 20; j++) {
                NRLog("  -[%s %s]", targets[i], sel_getName(method_getName(methods[j])));
            }
            if (count > 20) NRLog("  ...(%u more)", count - 20);
            free(methods);
        }
    }
}

static BOOL LooksLikeObjcMethod(uintptr_t addr) {
    uint32_t *p = (uint32_t *)addr;
    uint32_t first = p[0];
    uint32_t second = p[1];
    uint32_t adrp = first & 0x9F000000;
    if (adrp == 0x90000000) {
        uint32_t next = second & 0xFC000000;
        if (next == 0x94000000) return YES;
        if (next == 0x14000000) return YES;
    }
    return NO;
}

static BOOL AddressInText(uintptr_t addr) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        if (addr >= (uintptr_t)hdr && addr < (uintptr_t)hdr + 0x40000000) {
            return YES;
        }
    }
    return NO;
}

static void DumpRvaProbe(void) {
    NRLog("--- rva probe ---");
    struct { const char *name; uint64_t rva; } items[] = {
        {"GameButton_ctor",          RVA_GAMEBUTTON_CTOR},
        {"Character_ctor",           RVA_CHARACTER_CTOR},
        {"Stage_setViewport",        RVA_STAGE_SETVIEWPORT},
        {"Stage_ctor",               RVA_STAGE_CTOR},
        {"HomePage_ctor",            RVA_HOMEPAGE_CTOR},
        {"MovieClip_ctor",           RVA_MOVIECLIP_CTOR},
        {"NativeFont_ctor",          RVA_NATIVEFONT_CTOR},
        {"NativeFont_formatString",  RVA_NATIVEFONT_FORMATSTRING},
        {"LogicDataTables_ctor",     RVA_LOGICDATATABLES_CTOR},
        {"LogicDataTables_init",     RVA_LOGICDATATABLES_INITDATATABLE},
        {"LogicProjectileData_ctor", RVA_LOGICPROJECTILEDATA_CTOR},
        {"LogicProjectileData_getI", RVA_LOGICPROJECTILEDATA_GETINTVALUE},
        {"MessageManager_ctor",      RVA_MESSAGEMANAGER_CTOR},
        {"MessageManager_recv",      RVA_MESSAGEMANAGER_RECEIVEMESSAGE},
        {NULL, 0}
    };
    for (int i = 0; items[i].name; i++) {
        uintptr_t addr = g_base + items[i].rva;
        NRLog("%-28s rva=0x%-8llx addr=%p inText=%d objc=%d",
              items[i].name, items[i].rva, (void*)addr,
              AddressInText(addr),
              LooksLikeObjcMethod(addr));
    }
}

typedef void (*MSHookMessageEx_t)(Class cls, SEL sel, IMP hook, IMP *old);
static MSHookMessageEx_t MSHookMessageEx_p = NULL;

static IMP g_orig_sendAction = NULL;
static int g_sendActionCount = 0;

static BOOL my_sendAction(id self, SEL _cmd, SEL action, id target, id sender, UIEvent *event) {
    g_sendActionCount++;
    if (g_sendActionCount < 30) {
        NRLog("sendAction #%d self=%s sel=%s target=%s",
              g_sendActionCount,
              object_getClassName(self),
              sel_getName(action),
              target ? object_getClassName(target) : "nil");
    }
    if (g_orig_sendAction) {
        return ((BOOL(*)(id,SEL,SEL,id,id,UIEvent*))g_orig_sendAction)(self, _cmd, action, target, sender, event);
    }
    return NO;
}

static void TestObjcHook(void) {
    NRLog("--- objc hook test ---");
    MSHookMessageEx_p = (MSHookMessageEx_t)dlsym(RTLD_DEFAULT, "MSHookMessageEx");
    NRLog("MSHookMessageEx = %p", MSHookMessageEx_p);
    if (!MSHookMessageEx_p) return;

    Class uiapp = objc_getClass("UIApplication");
    if (!uiapp) { NRLog("UIApplication class not found"); return; }

    SEL sel = sel_registerName("sendAction:to:from:forEvent:");
    IMP orig = NULL;
    MSHookMessageEx_p(uiapp, sel, (IMP)my_sendAction, &orig);
    g_orig_sendAction = orig;
    NRLog("hooked sendAction, orig=%p", orig);
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
        strncpy(g_image, path, sizeof(g_image) - 1);
        return YES;
    }
    return NO;
}

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
        @"NullRythm Diag",
        [NSString stringWithFormat:@"image: %s", g_image],
        [NSString stringWithFormat:@"base: 0x%lx", g_base],
        [NSString stringWithFormat:@"hooker: %p", dlsym(RTLD_DEFAULT, "MSHookFunction")],
        [NSString stringWithFormat:@"mex: %p", MSHookMessageEx_p],
        [NSString stringWithFormat:@"sendAction count: %d", g_sendActionCount],
        @"",
        @"Full log: Documents/NullRythm.log",
    ];
    for (NSString *line in lines) {
        UILabel *l = [UILabel new];
        l.text = line;
        l.textColor = [line isEqualToString:@"NullRythm Diag"]
            ? [UIColor systemYellowColor] : [UIColor whiteColor];
        l.font = [line isEqualToString:@"NullRythm Diag"]
            ? [UIFont boldSystemFontOfSize:16]
            : [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
        l.numberOfLines = 0;
        [self.stack addArrangedSubview:l];
    }

    __weak UILabel *counterLabel = self.stack.arrangedSubviews[5];
    [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t){
        counterLabel.text = [NSString stringWithFormat:@"sendAction count: %d", g_sendActionCount];
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
        g_win.frame = CGRectMake(50, 100, 320, 400);
        g_win.hidden = NO;
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_win action:@selector(nr_drag:)];
        [g_win addGestureRecognizer:pan];
    });
}

__attribute__((constructor))
static void nr_init(void) {
    NRLog("=== NullRythm diag init ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        DumpEnvironment();
        DumpDyldImages();
        DumpHooker();
        if (!DetectGame()) {
            NRLog("game not found");
            return;
        }
        NRLog(">>> game: %s base=%p", g_image, (void*)g_base);
        DumpRvaProbe();
        DumpObjcClasses();
        TestObjcHook();
        ShowMenu();
        NRLog("=== diag done ===");
    });
}