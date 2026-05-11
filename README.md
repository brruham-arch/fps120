# libfps120 — AML Mod Unlock 120 FPS

**GTA SA Android / SA-MP Mobile | ARM32 armeabi-v7a**

## Cara kerja

1. **Patch FPS cap floats** di `.data` libGTASA.so offset `0x6AFC7C` dan `0x6AFC80` dari `30.0f` → `120.0f`
2. **Hook `OS_ThreadSleep`** di offset `0x26A8AC` (Thumb) — skip sleep >4ms yang throttle frame rate

## Install

1. Copy `libfps120.so` ke:
   ```
   /storage/emulated/0/Android/data/com.sampmobilerp.game/mods/
   ```
2. Jalankan game

## Debug

Log tersimpan di: `/storage/emulated/0/fps120_log.txt`

```bash
tail -f /storage/emulated/0/fps120_log.txt
```

## Catatan

- Jika physics/speed game ikut kencang → engine frame-dependent → perlu patch `CTimer::ms_fTimeStep`
- Jika crash → FPS cap offset salah, coba offset lain dari hasil analisis
- Build: GitHub Actions NDK r25c armeabi-v7a
