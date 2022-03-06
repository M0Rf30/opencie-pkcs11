// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: GPL-2.0-or-later

#include "text_file_reader.h"

#include <fcntl.h>
#include <sys/stat.h>

// Construction/Destruction

UUCTextFileReader::UUCTextFileReader(const char* szFilePath) {
  m_pf = fopen(szFilePath, "rt");
  if (!m_pf) {
    throw static_cast<long>(ERROR_FILE_NOT_FOUND);
  }

#ifndef _WIN32
  struct stat lstat_buf;
  struct stat fstat_buf;

  int r = lstat(szFilePath, &lstat_buf);

  /* handle the case of the lstat failing first */
  if (r == -1) {
    fclose(m_pf);
    throw static_cast<long>(ERROR_FILE_NOT_FOUND);
  }

  if (S_ISLNK(lstat_buf.st_mode)) {
    fclose(m_pf);
    throw static_cast<long>(ERROR_FILE_NOT_FOUND);
  }

  /* Get the properties of the opened file descriptor */
  r = stat(szFilePath, &fstat_buf);
  if (r == -1) {
    fclose(m_pf);
    throw static_cast<long>(ERROR_FILE_NOT_FOUND);
  }

  if (lstat_buf.st_dev != fstat_buf.st_dev ||
      lstat_buf.st_ino != fstat_buf.st_ino ||
      (S_IFMT & lstat_buf.st_mode) != (S_IFMT & fstat_buf.st_mode)) {
    fclose(m_pf);
    throw static_cast<long>(ERROR_FILE_NOT_FOUND);
  }
#endif
}

UUCTextFileReader::~UUCTextFileReader() { fclose(m_pf); }

long UUCTextFileReader::readLine(UUCByteArray& line) {
  char szLine[2];
  unsigned int i = 0;
  while ((fread(szLine, 1, 1, m_pf) > 0) && (szLine[0] != '\n')) {
    i++;
    line.append(szLine[0]);
  }

  if (i > 0) {
    line.append(static_cast<BYTE>(0));
    return 0;
  } else if ((i == 0) && szLine[0] == '\n') {
    return readLine(line);
  } else {
    return -1;
  }
}

long UUCTextFileReader::readLine(char* szLine,
                                 unsigned long nLen) {  // throw (long)
  unsigned int i = 0;
  while ((fread(szLine + i, 1, 1, m_pf) > 0) && (szLine[i] != '\n')) {
    i++;
    if (i == nLen) {
      throw static_cast<long>(ERROR_MORE_DATA);
    }
  }

  if (i > 0) {
    szLine[i] = 0;
    return 0;
  } else if ((i == 0) && szLine[i] == '\n') {
    return readLine(szLine, nLen);
  } else {
    return -1;
  }
}
