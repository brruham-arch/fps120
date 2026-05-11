#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <android/log.h>
#include <stdlib.h>
#include <unistd.h>

#define LOG_TAG "libfps120"
#define LOGFILE "/storage/emulated/0/fps120_log.txt"
#define EXPORT  __attribute__((visibility("default")))

static void _log(const char* msg) {
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", msg);
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}
static void _logf(const char* fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    _log(buf);
}

static uintptr_t get_lib_base(const char* lib) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512]; uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, lib) && strstr(line, "r-xp")) {
            base = (uintptr_t)strtoul(line, nullptr, 16); break;
        }
    }
    fclose(f); return base;
}

// VA dari dynsym analysis
#define VA_NV_THREAD_SLEEP     0x0027A22D  // size=82, frame throttle kandidat kuat
#define VA_OS_THREAD_SLEEP     0x0026A8AD  // size=4
#define VA_DIAG_GET_FPS        0x003F54C5  // size=108, baca FPS engine
#define VA_DORWSTUFF_START     0x003F573D  // render loop start

static uintptr_t g_base = 0;

// --- Hook NVThreadSleep ---
static void (*orig_NVThreadSleep)(unsigned long ms) = nullptr;
static void hk_NVThreadSleep(unsigned long ms) {
    // Skip semua sleep — NVThreadSleep pakai milidetik
    if (ms >= 8) return;
    if (orig_NVThreadSleep) orig_NVThreadSleep(ms);
}

// --- Hook OS_ThreadSleep ---
static void (*orig_OS_ThreadSleep)(int ms) = nullptr;
static void hk_OS_ThreadSleep(int ms) {
    if (ms >= 8) return;
    if (orig_OS_ThreadSleep) orig_OS_ThreadSleep(ms);
}

// --- Hook usleep (libc) ---
static int (*orig_usleep)(useconds_t us) = nullptr;
static int hk_usleep(useconds_t us) {
    if (us >= 8000) return 0;
    return orig_usleep ? orig_usleep(us) : 0;
}

// --- Hook Diag_GetFPS untuk log FPS engine ---
static float (*orig_DiagGetFPS)(void) = nullptr;
static int g_fps_logged = 0;
static float hk_DiagGetFPS(void) {
    float fps = orig_DiagGetFPS ? orig_DiagGetFPS() : 0.0f;
    // Log tiap 300 call (~5 detik) untuk tidak spam
    static int counter = 0;
    if (++counter >= 300) {
        counter = 0;
        _logf("[FPS120] engine FPS = %.1f", fps);
    }
    return fps;
}

extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "fps120|3.0|Unlock FPS - hook NVThreadSleep+OS_ThreadSleep+usleep|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    _log("[FPS120] ===== OnModPreLoad v3.0 =====");
}

EXPORT void OnModLoad() {
    _log("[FPS120] ===== OnModLoad v3.0 =====");

    g_base = get_lib_base("libGTASA.so");
    _logf("[FPS120] base = 0x%08X", (unsigned)g_base);
    if (!g_base) { _log("[FPS120] ERROR: base not found"); return; }

    // Verifikasi VA dengan base
    uint8_t b[4];
    memcpy(b, (void*)(g_base + VA_NV_THREAD_SLEEP - 1), 4); // -1 Thumb
    _logf("[FPS120] NVThreadSleep bytes: %02X %02X %02X %02X", b[0],b[1],b[2],b[3]);
    memcpy(b, (void*)(g_base + VA_OS_THREAD_SLEEP - 1), 4);
    _logf("[FPS120] OS_ThreadSleep bytes: %02X %02X %02X %02X", b[0],b[1],b[2],b[3]);

    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { _log("[FPS120] ERROR: no dobby"); return; }

    auto Hook     = (int(*)(void*,void*,void**))dlsym(hDobby, "DobbyHook");
    auto Resolver = (void*(*)(const char*,const char*))dlsym(hDobby, "DobbySymbolResolver");
    if (!Hook || !Resolver) { _log("[FPS120] ERROR: dobby syms"); return; }

    // Hook NVThreadSleep (Thumb: VA|1 already odd, pass as-is)
    void* addr;
    int r;

    addr = (void*)(g_base + VA_NV_THREAD_SLEEP);
    r = Hook(addr, (void*)hk_NVThreadSleep, (void**)&orig_NVThreadSleep);
    _logf("[FPS120] NVThreadSleep hook: %s orig=%p", r==0?"OK":"FAIL", (void*)orig_NVThreadSleep);

    addr = (void*)(g_base + VA_OS_THREAD_SLEEP);
    r = Hook(addr, (void*)hk_OS_ThreadSleep, (void**)&orig_OS_ThreadSleep);
    _logf("[FPS120] OS_ThreadSleep hook: %s orig=%p", r==0?"OK":"FAIL", (void*)orig_OS_ThreadSleep);

    // Hook usleep via resolver
    addr = Resolver("libGTASA.so", "usleep");
    if (!addr) addr = dlsym(RTLD_DEFAULT, "usleep");
    if (addr) {
        r = Hook(addr, (void*)hk_usleep, (void**)&orig_usleep);
        _logf("[FPS120] usleep hook: %s orig=%p", r==0?"OK":"FAIL", (void*)orig_usleep);
    }

    // Hook Diag_GetFPS untuk monitor FPS engine
    addr = (void*)(g_base + VA_DIAG_GET_FPS);
    r = Hook(addr, (void*)hk_DiagGetFPS, (void**)&orig_DiagGetFPS);
    _logf("[FPS120] DiagGetFPS hook: %s orig=%p", r==0?"OK":"FAIL", (void*)orig_DiagGetFPS);

    _log("[FPS120] ===== DONE =====");
    _log("[FPS120] Pantau log - engine FPS akan muncul tiap ~5 detik");
}

} // extern "C"
