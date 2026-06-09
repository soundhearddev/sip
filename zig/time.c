#include <time.h>
#include <stdint.h>

uint32_t get_unix_time(void) {
    return (uint32_t)time(NULL);
}