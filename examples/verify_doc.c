/*
 * verify_doc.c — Verify a signed PDF or P7M document using cie_verify().
 *
 * Usage: ./verify_doc <signed_file>
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include "opencie/cie_ext.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <signed_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* path = argv[1];
    printf("Verifying: %s\n\n", path);

    /* NULL proxy = no proxy */
    CK_RV rv = cie_verify(path, NULL, 0, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "cie_verify failed: rv=0x%08lX\n", rv);
        return EXIT_FAILURE;
    }

    int count = (int)cie_get_sign_count();
    printf("Signatures found: %d\n\n", count);

    for (int i = 0; i < count; i++) {
        struct verifyInfo_t info = {0};
        CK_RV r = cie_get_verify_info(i, &info);
        if (r != CKR_OK) {
            fprintf(stderr, "  [%d] cie_get_verify_info failed: rv=0x%08lX\n", i, r);
            continue;
        }
        printf("  Signature %d:\n", i);
        printf("    Name:        %s %s\n", info.name, info.surname);
        printf("    CN:          %s\n", info.cn);
        printf("    Signed at:   %s\n", info.signingTime);
        printf("    CA DN:       %s\n", info.cadn);
        printf("    Sig valid:   %s\n", info.isSignValid  ? "YES" : "NO");
        printf("    Cert valid:  %s\n", info.isCertValid  ? "YES" : "NO");
        printf("    Cert revoc:  %d\n", info.CertRevocStatus);
        printf("\n");
    }

    return EXIT_SUCCESS;
}
