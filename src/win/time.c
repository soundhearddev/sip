#include <windows.h>

// Gibt die Sekunden seit Systemstart zurück
unsigned int get_windows_time_c() {
    return GetTickCount() / 1000;
}