// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

/**
 * True if the directory holding `filePath` is a real directory (not a
 * symlink) owned by the effective uid. O_NOFOLLOW on the file only covers
 * the last path component; without this check a symlinked ~/.CIEPKI would
 * redirect log and config files into an arbitrary directory.
 */
inline bool ParentDirIsPrivate(const std::string &filePath) {
  std::string dir = filePath.substr(0, filePath.find_last_of('/'));
  while (dir.size() > 1 && dir.back() == '/') dir.pop_back();
  if (dir.empty()) return false;
  int fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd == -1) return false;
  struct stat st {};
  bool ok =
      fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid();
  close(fd);
  return ok;
}
#endif
