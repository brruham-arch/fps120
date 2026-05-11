#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <android/log.h>
#include <unistd.h>

// ============================================================
//  CONFIG
// ============================================================
#define LOG_TAG   "libfps120"
#define LOGFILE   "/storage/emulated/0/fps120_log.txt"
#define EXPORT    __attribute__((visibility("default")))

// Target FPS
#define TARGET_FPS   120.0f

// Offset dalam libGTASA.so (dari analisis binary)
// OS_ThreadSleep — Thumb, bit-0 sudah dikurangi (alamat genap)
#define OFF_OS_THREAD_SLEEP   0x26A8AC

// 30.0f candidates di .data — pair FPS cap paling mungkin
#define OFF_FPS_CAP_1         0x6AFC7C
#define OFF_FPS_CAP_2         0x6AFC80

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
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _log(buf);
}

// ============================================================
//  STATE
// ============================================================
static uintptr_t g_base         = 0;
static int       g_hooked       = 0;
static int       g_patched      = 0;

// ============================================================
//  HOOK — OS_ThreadSleep
// ============================================================
static void (*orig_OS_ThreadSleep)(int ms) = nullptr;

static void hk_OS_ThreadSleep(int ms) {
    // Skip frame-throttle sleep (>4ms) agar FPS tidak di-cap
    // Sleep kecil (<=4ms) tetap dilewat untuk idle thread
    if (ms > 4) return;
    if (orig_OS_ThreadSleep) orig_OS_ThreadSleep(ms);
}

// ============================================================
//  HELPERS
// ============================================================
static void* _dobby_hook   = nullptr;
static void* _dobby_sym    = nullptr;

// Baca float dari offset relative ke base (debug)
static float _read_float(uintptr_t offset) {
    float val = 0.0f;
    uintptr_t addr = g_base + offset;
    memcpy(&val, (void*)addr, sizeof(float));
    return val;
}

// Tulis float ke offset relative ke base
static void _write_float(uintptr_t offset, float val) {
    uintptr_t addr = g_base + offset;
    memcpy((void*)addr, &val, sizeof(float));
}

// ============================================================
//  ENTRY POINTS
// ============================================================
extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "fps120|1.0|Unlock 120 FPS via OS_ThreadSleep hook + FPS cap patch|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    // Reset log
    remove(LOGFILE);
    _log("[FPS120] ========== OnModPreLoad ==========");
    _log("[FPS120] v1.0 | brruham-arch");
    _log("[FPS120] Target: libGTASA.so ARM32 Thumb2");
}

EXPORT void OnModLoad() {
    _log("[FPS120] ========== OnModLoad ==========");

    // --- 1. Dapatkan base libGTASA.so ---
    void* hGTASA = dlopen("libGTASA.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hGTASA) {
        _log("[FPS120] ERROR: dlopen libGTASA.so gagal");
        return;
    }
    g_base = (uintptr_t)hGTASA;
    _logf("[FPS120] libGTASA.so base = 0x%08X", (unsigned)g_base);

    // --- 2. Load Dobby ---
    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) {
        _log("[FPS120] ERROR: dlopen libdobby.so gagal");
        return;
    }
    _log("[FPS120] libdobby.so loaded OK");

    auto dobbyHook = (int(*)(void*, void*, void**))dlsym(hDobby, "DobbyHook");
    if (!dobbyHook) {
        _log("[FPS120] ERROR: DobbyHook symbol tidak ditemukan");
        return;
    }
    _log("[FPS120] DobbyHook symbol OK");

    // --- 3. Log nilai sebelum patch ---
    float before1 = _read_float(OFF_FPS_CAP_1);
    float before2 = _read_float(OFF_FPS_CAP_2);
    _logf("[FPS120] BEFORE patch: [0x%X]=%.2f [0x%X]=%.2f",
          OFF_FPS_CAP_1, before1,
          OFF_FPS_CAP_2, before2);

    // --- 4. Patch FPS cap floats di .data ---
    _write_float(OFF_FPS_CAP_1, TARGET_FPS);
    _write_float(OFF_FPS_CAP_2, TARGET_FPS);
    g_patched = 1;

    float after1 = _read_float(OFF_FPS_CAP_1);
    float after2 = _read_float(OFF_FPS_CAP_2);
    _logf("[FPS120] AFTER  patch: [0x%X]=%.2f [0x%X]=%.2f",
          OFF_FPS_CAP_1, after1,
          OFF_FPS_CAP_2, after2);

    if (after1 == TARGET_FPS && after2 == TARGET_FPS) {
        _log("[FPS120] FPS cap patch: BERHASIL");
    } else {
        _log("[FPS120] FPS cap patch: GAGAL (nilai tidak berubah — memory mungkin read-only)");
    }

    // --- 5. Hook OS_ThreadSleep (Thumb = offset + 1) ---
    // OS_ThreadSleep ada di .text, terpanggil tiap frame untuk throttle
    uintptr_t sleepAddr = g_base + OFF_OS_THREAD_SLEEP + 1; // +1 = Thumb mode
    _logf("[FPS120] OS_ThreadSleep target addr = 0x%08X", (unsigned)sleepAddr);

    // Baca 4 byte pertama untuk verifikasi (Thumb BL)
    uint8_t bytes[4];
    memcpy(bytes, (void*)(sleepAddr - 1), 4);
    _logf("[FPS120] OS_ThreadSleep bytes: %02X %02X %02X %02X",
          bytes[0], bytes[1], bytes[2], bytes[3]);

    int ret = dobbyHook((void*)sleepAddr,
                        (void*)hk_OS_ThreadSleep,
                        (void**)&orig_OS_ThreadSleep);
    if (ret == 0) {
        g_hooked = 1;
        _logf("[FPS120] OS_ThreadSleep hook: BERHASIL (orig=%p)", (void*)orig_OS_ThreadSleep);
    } else {
        _logf("[FPS120] OS_ThreadSleep hook: GAGAL (ret=%d)", ret);
    }

    // --- 6. Ringkasan ---
    _log("[FPS120] ========== RINGKASAN ==========");
    _logf("[FPS120] g_base    = 0x%08X", (unsigned)g_base);
    _logf("[FPS120] patched   = %d", g_patched);
    _logf("[FPS120] hooked    = %d", g_hooked);
    _logf("[FPS120] target    = %.1f FPS", TARGET_FPS);
    _log("[FPS120] ================================");
    _log("[FPS120] OnModLoad SELESAI");
    _log("[FPS120] >> Jika physics/speed ikut kencang: CTimer::ms_fTimeStep");
    _log("[FPS120] >> perlu diclamp. Lihat log lebih lanjut.");
}

} // extern "C"
