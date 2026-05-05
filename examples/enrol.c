/*
 * enrol.c — Enrol a CIE card using cie_enable().
 *
 * Usage: ./enrol <PAN> <PIN>
 *   PAN: 16-digit card PAN printed on the card
 *   PIN: 8-digit numeric PIN
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

static CK_RV on_complete(const char* pan, const char* name,
                         const char* serial) {
  printf("\nEnrolment complete:\n");
  printf("  PAN:    %s\n", pan ? pan : "(null)");
  printf("  Name:   %s\n", name ? name : "(null)");
  printf("  Serial: %s\n", serial ? serial : "(null)");
  return CKR_OK;
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <PAN> <PIN>\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char* pan = argv[1];
  const char* pin = argv[2];
  int attempts = -1;

  printf("Enrolling card PAN=%s ...\n", pan);

  CK_RV rv = cie_enable(pan, pin, &attempts, on_progress, on_complete);

  if (rv != CKR_OK) {
    fprintf(stderr, "cie_enable failed: rv=0x%08lX", rv);
    if (attempts >= 0)
      fprintf(stderr, " (PIN attempts remaining: %d)", attempts);
    fprintf(stderr, "\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
