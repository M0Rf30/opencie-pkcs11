// SPDX-License-Identifier: LGPL-3.0-or-later
#include "syncro_event.h"

void auto_reset_event::set() {
  {
    std::unique_lock<std::mutex> lock(m_);
    signaled_ = true;
  }

  cv_.notify_one();
}

void auto_reset_event::wait() {
  std::unique_lock<std::mutex> lock(m_);
  while (!signaled_) cv_.wait(lock);
  signaled_ = false;
}
