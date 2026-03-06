// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file syncro_mutex.h
 * @brief Mutex synchronization primitives for thread safety.
 *
 * Provides a named/unnamed mutex wrapper and an RAII lock guard
 * for use in the CIE PKCS#11 library.
 */

#pragma once
#include "util/util.h"

/**
 * @brief Wrapper around a platform mutex handle.
 *
 * Provides named and unnamed mutex creation with explicit
 * Lock/Unlock semantics. Prefer using CSyncroLocker for
 * RAII-based locking.
 */
class CSyncroMutex {
  HANDLE hMutex; /**< Platform-specific mutex handle. */

 public:
  /** @brief Create an unnamed mutex. */
  void Create(void);

  /** @brief Default constructor. Does not create the mutex. */
  CSyncroMutex(void);

  /**
   * @brief Create a named mutex.
   * @param name System-wide name for the mutex.
   */
  void Create(const char *name);

  /** @brief Destructor. Releases the mutex handle. */
  ~CSyncroMutex(void);

  /** @brief Acquire the mutex lock (blocking). */
  void Lock();

  /** @brief Release the mutex lock. */
  void Unlock();
};

/**
 * @brief RAII lock guard for CSyncroMutex.
 *
 * Acquires the mutex on construction and releases it on destruction,
 * ensuring the lock is always released even in the presence of exceptions.
 */
class CSyncroLocker {
  CSyncroMutex *pMutex; /**< Pointer to the managed mutex. */

 public:
  /**
   * @brief Construct and acquire the lock.
   * @param mutex Mutex to lock.
   */
  CSyncroLocker(CSyncroMutex &mutex);

  /** @brief Destructor. Releases the mutex lock. */
  ~CSyncroLocker();
};
