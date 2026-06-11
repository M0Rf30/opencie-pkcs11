/*
 * timestamp.c — Request a RFC 3161 timestamp for a file using cie_timestamp().
 *
 * Usage: ./timestamp <input_file> <tsa_url> <output.tst> [username] [password]
 *   input_file: Path to the file to timestamp
 *   tsa_url: URL of the Time Stamp Authority (e.g., https://freetsa.org/tst)
 *   output.tst: Output file for the DER-encoded TimeStampToken
 *   username: Optional HTTP Basic auth username (pass empty string if not
 * needed) password: Optional HTTP Basic auth password (pass empty string if not
 * needed)
 *
 * Note: This function does not require a CIE card. A public free TSA is
 * available at https://freetsa.org/tst for testing purposes.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opencie/cie_ext.h"

static CK_RV on_progress(int pct, const char* msg) {
  printf("[%3d%%] %s\n", pct, msg ? msg : "");
  return CKR_OK;
}

int main(int argc, char* argv[]) {
  if (argc < 4 || argc > 6) {
    fprintf(stderr,
            "Usage: %s <input_file> <tsa_url> <output.tst> [username] "
            "[password]\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  const char* input_file = argv[1];
  const char* tsa_url = argv[2];
  const char* output_tst = argv[3];
  const char* username = argc > 4 ? argv[4] : NULL;
  const char* password = argc > 5 ? argv[5] : NULL;

  /* Convert empty strings to NULL for optional parameters */
  if (username && strlen(username) == 0) username = NULL;
  if (password && strlen(password) == 0) password = NULL;

  printf("Requesting timestamp for %s\n", input_file);
  printf("TSA URL: %s\n", tsa_url);
  if (username) printf("Using HTTP Basic auth with username: %s\n", username);

  CK_RV rv = cie_timestamp(input_file, tsa_url, username, password, output_tst,
                           on_progress);

  if (rv != CKR_OK) {
    fprintf(stderr, "cie_timestamp failed: rv=0x%08lX\n", rv);
    return EXIT_FAILURE;
  }

  printf("\nTimestamp token written to: %s\n", output_tst);
  return EXIT_SUCCESS;
}
