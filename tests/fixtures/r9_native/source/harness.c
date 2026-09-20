#include <stdio.h>
#include <stdlib.h>

void parse_packet(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
    static const unsigned char magic[] = "VULNLOOM";
    unsigned char input[1024];
    size_t size;
    size_t coverage = 0;
    FILE *stream;
    if (argc != 2) {
        return 2;
    }
    stream = fopen(argv[1], "rb");
    if (stream == NULL) {
        return 3;
    }
    size = fread(input, 1, sizeof(input), stream);
    if (ferror(stream)) {
        fclose(stream);
        return 4;
    }
    fclose(stream);
    while (coverage < size && coverage < sizeof(magic) - 1 &&
           input[coverage] == magic[coverage]) {
        coverage++;
    }
    printf("COVERAGE:%zu\n", coverage);
    fflush(stdout);
    parse_packet(input, size);
    return 0;
}
