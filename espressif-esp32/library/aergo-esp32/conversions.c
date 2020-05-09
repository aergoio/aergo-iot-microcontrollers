//#include <stdio.h>
//#include <stdint.h>
#include "mbedtls/bignum.h"

// convert a value from big endian variable integer to string with
// decimal point. uses 18 decimal digits
int bignum_to_string(uint8_t *buf, int len, uint8_t *out, int outlen) {
    mbedtls_mpi value;
    char tmp[36];
    int i;

    mbedtls_mpi_init(&value);
    if (mbedtls_mpi_read_binary(&value, buf, len) != 0) goto loc_failed;
    if (mbedtls_mpi_write_string(&value, 10, out, outlen, &len) != 0) goto loc_failed;
    mbedtls_mpi_free(&value);

    // align the string to the right
    snprintf(tmp, sizeof(tmp), "%32s", out);

    // replace the spaces with zeros
    for (i = 0; tmp[i] == ' '; i++) {
        tmp[i] = '0';
        len++;
    }

    // add the decimal point
    snprintf(out, outlen, "%.*s.%s", 32-18, tmp, tmp+32-18);

    // return the size
    return len + 1;

loc_failed:
    mbedtls_mpi_free(&value);
    return -1;
}

// convert a value from string format to big endian variable integer.
// the string can optionally have a decimal point. uses 18 decimal digits
int string_to_bignum(uint8_t *str, int len, uint8_t *out, int outlen) {
    mbedtls_mpi value;
    char integer[36], decimal[36], *p;
    int i;

    p = strchr(str, '.');
    if (p) {
        // copy the integer part
        snprintf(integer, sizeof(integer), "%.*s", (int)(p-str), str);
        // copy the decimal part
        p++;
        for (i = 0; i < 18 && *p; i++) {
            decimal[i] = *p++;
        }
    } else {
        strcpy(integer, str);
        i = 0;
    }

    // fill the decimal with trailing zeros
    for (; i < 18; i++) {
        decimal[i] = '0';
    }
    // null terminator
    decimal[18] = 0;

    // contatenate both parts
    strcat(integer, decimal);

    // convert it to big endian variable size integer
    mbedtls_mpi_init(&value);
    if (mbedtls_mpi_read_string(&value, 10, integer) != 0) goto loc_failed;
    if (mbedtls_mpi_write_binary(&value, out, outlen) != 0) goto loc_failed;
    len = mbedtls_mpi_size(&value);
    mbedtls_mpi_free(&value);

    return len;
}
