// UUCTextFileWriter.h: interface for the UUCTextFileWriter class.
//

#pragma once

#include <cstdio>

#include "Util/byte_array.h"

class UUCTextFileWriter {
 public:
  UUCTextFileWriter(const char* szFilePath, bool bAppend = false);
  virtual ~UUCTextFileWriter();

  long writeLine(const char* szLine);
  long writeLine(const UUCByteArray& byteArray);

 private:
  FILE* m_pf;
};


