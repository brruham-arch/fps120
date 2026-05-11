#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <android/log.h>
#include <unistd.h>
#include <stdlib.h>

#define LOG_TAG   "libfps120"
#define LOGFILE   "/storage/emulated/0/fps120_log.txt"
#define EXPORT    __attribute__((visibility("default")))

// ============================================================
//  LOGGING
// ============================================================
static void _log(const char* msg) {
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", msg);
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}
static void _logf(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _log(buf);
}

// ============================================================
//  BACA BASE DARI /proc/self/maps (CARA BENAR ARM32)
// ============================================================
static uintptr_t get_lib_base(const char* libname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname) && strstr(line, "r-xp")) {
            base = (uintptr_t)strtoul(line, nullptr, 16);
            break;
        }
    }
    fclose(f);
    return base;
}

// ============================================================
//  STATE
// ============================================================
static uintptr_t g_base_gtasa = 0;
static uintptr_t g_base_samp  = 0;

// ============================================================
//  HOOK — usleep
// ============================================================
static int (*orig_usleep)(useconds_t us) = nullptr;

static int hk_usleep(useconds_t us) {
    // Skip frame-throttle sleep (>= 8ms = 125fps ceiling)
    if (us >= 8000) return 0;
    return orig_usleep ? orig_usleep(us) : 0;
}

// ============================================================
//  HOOK — nanosleep
// ============================================================
struct nano_timespec { long tv_sec; long tv_nsec; };
static int (*orig_nanosleep)(const nano_timespec*, nano_timespec*) = nullptr;

static int hk_nanosleep(const nano_timespec* req, nano_timespec* rem) {
    if (req && (req->tv_sec > 0 || req->tv_nsec >= 8000000)) return 0;
    return orig_nanosleep ? orig_nanosleep(req, rem) : 0;
}

// ============================================================
//  ENTRY POINTS
// ============================================================
extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "fps120|2.0|Unlock 120 FPS via usleep+nanosleep hook|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    _log("[FPS120] ========== OnModPreLoad v2.0 ==========");
    _log("[FPS120] Strategy: hook usleep+nanosleep, base dari /proc/self/maps");
}

EXPORT void OnModLoad() {
    _log("[FPS120] ========== OnModLoad v2.0 ==========");

    // 1. Base address dari maps (bukan dlopen handle)
    g_base_gtasa = get_lib_base("libGTASA.so");
    g_base_samp  = get_lib_base("libsamp.so");
    _logf("[FPS120] libGTASA.so base = 0x%08X", (unsigned)g_base_gtasa);
    _logf("[FPS120] libsamp.so  base = 0x%08X", (unsigned)g_base_samp);

    // 2. Verifikasi ELF magic di base
    if (g_base_gtasa) {
        uint8_t* m = (uint8_t*)g_base_gtasa;
        _logf("[FPS120] ELF magic: %02X %02X %02X %02X", m[0],m[1],m[2],m[3]);

        // Verifikasi OS_ThreadSleep bytes dengan base yang benar
        uint8_t sb[4];
        memcpy(sb, (void*)(g_base_gtasa + 0x26A8AC), 4);
        _logf("[FPS120] OS_ThreadSleep@base+0x26A8AC: %02X %02X %02X %02X",
              sb[0],sb[1],sb[2],sb[3]);
    }

    // 3. Load Dobby
    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { _log("[FPS120] ERROR: libdobby tidak ada"); return; }
    _log("[FPS120] libdobby OK");

    auto dobbyHook     = (int(*)(void*,void*,void**))dlsym(hDobby, "DobbyHook");
    auto dobbyResolver = (void*(*)(const char*,const char*))dlsym(hDobby, "DobbySymbolResolver");
    if (!dobbyHook || !dobbyResolver) {
        _log("[FPS120] ERROR: Dobby symbols tidak lengkap");
        return;
    }

    // 4. Hook usleep
    void* usleep_addr = dobbyResolver("libGTASA.so", "usleep");
    _logf("[FPS120] usleep via resolver = %p", usleep_addr);
    if (!usleep_addr) {
        usleep_addr = dlsym(RTLD_DEFAULT, "usleep");
        _logf("[FPS120] usleep via dlsym   = %p", usleep_addr);
    }
    if (usleep_addr) {
        int r = dobbyHook(usleep_addr, (void*)hk_usleep, (void**)&orig_usleep);
        _logf("[FPS120] usleep hook: %s ret=%d orig=%p",
              r==0?"OK":"FAIL", r, (void*)orig_usleep);
    }

    // 5. Hook nanosleep
    void* nano_addr = dobbyResolver("libGTASA.so", "nanosleep");
    _logf("[FPS120] nanosleep via resolver = %p", nano_addr);
    if (!nano_addr) {
        nano_addr = dlsym(RTLD_DEFAULT, "nanosleep");
        _logf("[FPS120] nanosleep via dlsym   = %p", nano_addr);
    }
    if (nano_addr) {
        int r = dobbyHook(nano_addr, (void*)hk_nanosleep, (void**)&orig_nanosleep);
        _logf("[FPS120] nanosleep hook: %s ret=%d orig=%p",
              r==0?"OK":"FAIL", r, (void*)orig_nanosleep);
    }

    // 6. Dump maps relevan
    {
        FILE* fm = fopen("/proc/self/maps", "r");
        FILE* fo = fopen("/storage/emulated/0/fps120_maps.txt", "w");
        if (fm && fo) {
            char line[512];
            while (fgets(line, sizeof(line), fm)) {
                if (strstr(line,"libGTASA")||strstr(line,"libsamp")||
                    strstr(line,"libdobby")||strstr(line,"libc.so"))
                    fputs(line, fo);
            }
            fclose(fm); fclose(fo);
            _log("[FPS120] maps -> /storage/emulated/0/fps120_maps.txt");
        }
    }

    // 7. Ringkasan
    _log("[FPS120] ========== RINGKASAN ==========");
    _logf("[FPS120] base_gtasa    = 0x%08X", (unsigned)g_base_gtasa);
    _logf("[FPS120] usleep hooked = %d", orig_usleep   ? 1:0);
    _logf("[FPS120] nano hooked   = %d", orig_nanosleep? 1:0);
    _log("[FPS120] ==================================");
    _log("[FPS120] Cek fps120_maps.txt untuk validasi base");
    _log("[FPS120] OnModLoad SELESAI");
}

} // extern "C"
