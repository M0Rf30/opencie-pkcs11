// UUCTextFileWriter.cpp: implementation of the UUCTextFileWriter class.
#include "text_file_writer.h"

#include <vector>
// Construction/Destruction
UUCTextFileWriter::UUCTextFileWriter(const char* szFilePath,
                                     bool bAppend /*= false*/) {
  if (bAppend)
    m_pf = fopen(szFilePath, "a+t");
  else
    m_pf = fopen(szFilePath, "wt");

  if (!m_pf) throw static_cast<long>(ERROR_FILE_NOT_FOUND);
}

UUCTextFileWriter::~UUCTextFileWriter() { fclose(m_pf); }

long UUCTextFileWriter::writeLine(const char* szLine) {
  if (fprintf(m_pf, "%s\n", szLine) < 0) return -1;

  fflush(m_pf);

  return 0;
}

long UUCTextFileWriter::writeLine(const UUCByteArray& byteArray) {
  std::vector<char> buf(byteArray.getLength() + 1);
  memcpy(buf.data(), byteArray.getContent(), byteArray.getLength());
  buf[byteArray.getLength()] = '\0';

  if (fprintf(m_pf, "%s\n", buf.data()) < 0) {
    return -1;
  }
  fflush(m_pf);

  return 0;
}
