// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file syncro_event.h
 * @brief Auto-reset event synchronization primitive.
 *
 * Provides a thread synchronization event that automatically resets
 * after a waiting thread is released, similar to Windows auto-reset events.
 */

#pragma once

#include <condition_variable>
#include <mutex>

/**
 * @brief Auto-reset event for thread synchronization.
 *
 * When set(), one waiting thread is released and the event
 * automatically returns to the non-signaled state. If no thread
 * is waiting, the next call to wait() will return immediately.
 */
class auto_reset_event {
 public:
  /**
   * @brief Construct an auto-reset event.
   * @param signaled Initial signaled state (default: non-signaled).
   */
  auto_reset_event(bool signaled = false) : signaled_(signaled) {}

  /** @brief Signal the event, releasing one waiting thread. */
  void set();

  /** @brief Block until the event is signaled, then auto-reset. */
  void wait();

 private:
  std::mutex m_;               /**< Mutex protecting the signaled state. */
  std::condition_variable cv_; /**< Condition variable for wait/notify. */
  bool signaled_;              /**< Current signaled state. */
};
