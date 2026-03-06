// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * @file func_call_info.h
 * @brief Function call tracing and logging support.
 *
 * Provides RAII-based function call tracing that logs entry/exit events
 * for diagnostic purposes in the CIE PKCS#11 library.
 */

#pragma once

#include <memory>

#include "log.h"

/**
 * @brief RAII helper that logs function entry and exit.
 *
 * On construction, records the function name and logs an entry event.
 * On destruction, logs the corresponding exit event. Used via the
 * init_func macro defined in defines.h.
 */
class CFuncCallInfo {
  const char *fName;   /**< Name of the traced function. */
  unsigned int LogNum; /**< Log sequence number at entry. */
  CLog &log;           /**< Reference to the logger instance. */

 public:
  /**
   * @brief Construct a function call trace entry.
   * @param name Function name (typically __FUNCTION__).
   * @param logInfo Logger to write trace events to.
   */
  CFuncCallInfo(const char *name, CLog &logInfo);

  /** @brief Destructor. Logs the function exit event. */
  ~CFuncCallInfo();

  /**
   * @brief Get the traced function name.
   * @return The function name string.
   */
  const char *FunctionName();
};

/**
 * @brief Linked list node for tracking nested function call traces.
 */
class CFuncCallInfoList {
 public:
  /**
   * @brief Construct a list node.
   * @param info Pointer to the function call info object.
   */
  CFuncCallInfoList(CFuncCallInfo *info) : info(info) {}

  CFuncCallInfo *info; /**< Function call info for this node. */
  std::unique_ptr<CFuncCallInfoList> next =
      nullptr; /**< Next node in the list. */
};
