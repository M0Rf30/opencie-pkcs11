/*
 * sign_pdf.c — Sign a PDF file using cie_sign().
 *
 * Usage: ./sign_pdf <PAN> <PIN> <input.pdf> <output.pdf>
 *
 * Places a visible signature widget on page 0 at position (10,10),
 * size 200x50 PDF points, with no stamp image.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include "opencie/cie_ext.h"

static CK_RV on_progress(int pct, const char* msg) {
    printf("[%3d%%] %s\n", pct, msg ? msg : "");
    return CKR_OK;
}

static CK_RV on_sign_done(int ret) {
    if (ret == 0)
        printf("\nSigning completed successfully.\n");
    else
        fprintf(stderr, "\nSigning failed (ret=%d).\n", ret);
    return CKR_OK;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <PAN> <PIN> <input.pdf> <output.pdf>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* pan     = argv[1];
    const char* pin     = argv[2];
    const char* in_pdf  = argv[3];
    const char* out_pdf = argv[4];

    printf("Signing %s -> %s\n", in_pdf, out_pdf);

    CK_RV rv = cie_sign(
        in_pdf,       /* input file path  */
        "PDF",        /* signature type   */
        pin,          /* card PIN         */
        pan,          /* card PAN         */
        0,            /* page index       */
        10.0f,        /* x (points)       */
        10.0f,        /* y (points)       */
        200.0f,       /* width (points)   */
        50.0f,        /* height (points)  */
        NULL, 0,      /* no stamp image   */
        out_pdf,      /* output file path */
        on_progress,
        on_sign_done
    );

    if (rv != CKR_OK) {
        fprintf(stderr, "cie_sign returned rv=0x%08lX\n", rv);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
