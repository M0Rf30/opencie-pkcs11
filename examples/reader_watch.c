/*
 * reader_watch.c — Monitor smart-card reader hot-plug events.
 *
 * Prints the current reader count and name, then blocks waiting for
 * changes. Press Ctrl-C to exit.
 *
 * Usage: ./reader_watch
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include "opencie/cie_ext.h"

int main(void) {
    printf("Watching for smart-card reader changes. Press Ctrl-C to exit.\n\n");

    int current = cie_reader_count();

    for (;;) {
        char name[256] = {0};
        cie_reader_name(name, sizeof(name));

        printf("Readers connected: %d", current);
        if (current > 0 && name[0])
            printf("  (first: \"%s\")", name);
        printf("\n");

        /* Block until the count changes */
        current = cie_reader_watch(current);
    }

    return EXIT_SUCCESS;
}
