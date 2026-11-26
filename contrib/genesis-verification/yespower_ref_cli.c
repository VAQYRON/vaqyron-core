/*
 * Copyright (c) 2026-present The VAQYRON developers
 *
 * This small adapter links only to the repository's separately compiled
 * yespower reference implementation. The upstream implementation's copyright
 * and redistribution terms remain in contrib/pow-prototype/deps/yespower.
 */

#include <yespower.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char PERSONALIZATION[] = "VAQYRON:pow:yespower:v1";

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    value = (char)tolower((unsigned char)value);
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    unsigned char header[80];
    yespower_binary_t digest;
    const yespower_params_t params = {
        YESPOWER_1_0, 2048, 16,
        (const uint8_t *)PERSONALIZATION, sizeof(PERSONALIZATION) - 1
    };
    size_t i;

    if (argc != 2) {
        fprintf(stderr, "usage: yespower-ref-cli <160-hex-character-header>\n");
        return 2;
    }
    if (strlen(argv[1]) != sizeof(header) * 2) {
        fprintf(stderr, "header must be exactly 160 hexadecimal characters\n");
        return 2;
    }
    for (i = 0; i < sizeof(header); ++i) {
        const int high = hex_value(argv[1][i * 2]);
        const int low = hex_value(argv[1][i * 2 + 1]);
        if (high < 0 || low < 0) {
            fprintf(stderr, "header contains a non-hexadecimal character\n");
            return 2;
        }
        header[i] = (unsigned char)((high << 4) | low);
    }

    if (yespower_tls(header, sizeof(header), &params, &digest) != 0) {
        fprintf(stderr, "reference yespower computation failed\n");
        return 1;
    }

    printf("POW_DIGEST=");
    for (i = 0; i < sizeof(digest.uc); ++i) {
        printf("%02x", digest.uc[i]);
    }
    putchar('\n');
    return 0;
}
