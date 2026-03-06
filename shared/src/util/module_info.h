// SPDX-FileCopyrightText: 2021 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file module_info.h
 * @brief Module path and identity information.
 *
 * Provides the CModuleInfo class for resolving and storing the
 * full path, directory, and name of a loaded library module.
 */

#include <string>

#include "util/util.h"

/**
 * @brief Stores path and identity information for a loaded module.
 *
 * Used to determine the location of the PKCS#11 shared library
 * at runtime, enabling relative path resolution for configuration
 * and resource files.
 */
class CModuleInfo {
  HANDLE module; /**< Platform-specific module handle. */

 public:
  std::string szModuleFullPath; /**< Full absolute path to the module file. */
  std::string szModulePath;     /**< Directory containing the module. */
  std::string szModuleName;     /**< File name of the module (without path). */

  /** @brief Default constructor. */
  CModuleInfo(void);

  /** @brief Virtual destructor. */
  virtual ~CModuleInfo(void);

  /**
   * @brief Get the handle of the current application module.
   * @return Module handle for the running application.
   */
  static HANDLE getApplicationModule();

  /**
   * @brief Get the stored module handle.
   * @return The module handle.
   */
  HANDLE getModule();

  /**
   * @brief Initialize with a module handle and resolve paths.
   * @param module Platform-specific module handle.
   */
  void init(HANDLE module);
};
