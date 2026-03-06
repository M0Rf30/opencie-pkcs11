// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file ldap_crl.h
 * @brief LDAP-based Certificate Revocation List (CRL) retrieval.
 */

#pragma once

/**
 * Fetch a CRL from the LDAP distribution point at @p url.
 *
 * @param url   LDAP URL of the CRL distribution point.
 * @param data  Output buffer receiving the raw CRL data.
 * @return 0 on success, non-zero error code on failure.
 */
long getCRLFromLDAP(char* url, ByteDynArray& data);
