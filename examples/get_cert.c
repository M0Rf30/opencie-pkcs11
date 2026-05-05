/*
 * get_cert.c — Retrieve the DER-encoded X.509 certificate for an enrolled card.
 *
 * Usage: ./get_cert <PAN> [output.der]
 *   If output.der is omitted, prints the hex dump to stdout.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>

#include "opencie/cie_ext.h"

int main(int argc, char* argv[]) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: %s <PAN> [output.der]\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char* pan = argv[1];
  const char* outf = argc == 3 ? argv[2] : NULL;
  unsigned char* der = NULL;
  unsigned long derLen = 0;

  CK_RV rv = cie_get_certificate(pan, &der, &derLen);
  if (rv != CKR_OK) {
    fprintf(stderr, "cie_get_certificate failed: rv=0x%08lX\n", rv);
    return EXIT_FAILURE;
  }

  printf("Certificate length: %lu bytes\n", derLen);

  if (outf) {
    FILE* f = fopen(outf, "wb");
    if (!f) {
      perror(outf);
      free(der);
      return EXIT_FAILURE;
    }
    fwrite(der, 1, derLen, f);
    fclose(f);
    printf("Written to: %s\n", outf);
  } else {
    /* Hex dump */
    for (unsigned long i = 0; i < derLen; i++) {
      printf("%02X", der[i]);
      if ((i + 1) % 16 == 0)
        printf("\n");
      else if ((i + 1) % 8 == 0)
        printf("  ");
      else
        printf(" ");
    }
    printf("\n");
  }

  free(der);
  return EXIT_SUCCESS;
}
