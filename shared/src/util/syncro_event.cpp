// SPDX-License-Identifier: LGPL-3.0-or-later
#include "syncro_event.h"

void auto_reset_event::set() {
  {
    std::unique_lock<std::mutex> lock(m_);
    ++pending_;
  }

  cv_.notify_one();
}

void auto_reset_event::wait() {
  std::unique_lock<std::mutex> lock(m_);
  while (pending_ == 0) cv_.wait(lock);
  --pending_;
}
