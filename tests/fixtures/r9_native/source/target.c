#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void parse_packet(const unsigned char *data, size_t size) {
    if (size >= 8 && memcmp(data, "VULNLOOM", 8) == 0) {
        volatile unsigned char *buffer = malloc(4);
        if (buffer == NULL) {
            abort();
        }
        for (size_t index = 0; index < size; index++) {
            buffer[index] = data[index];
        }
        free((void *)buffer);
    }
}
