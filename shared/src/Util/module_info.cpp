#include "module_info.h"

#include "Util/util_exception.h"

CModuleInfo::CModuleInfo() {}

HANDLE CModuleInfo::getModule() { return module; }

#ifdef _WIN32

HANDLE CModuleInfo::getApplicationModule() {
  return (HANDLE)GetModuleHandle(nullptr);
}

void CModuleInfo::init(HANDLE module) {
  this->module = module;
  char path[MAX_PATH];
  if (GetModuleFileName((HMODULE)module, path, MAX_PATH) == 0)
    throw windows_error(GetLastError());

  szModuleFullPath = path;

  char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], ext[_MAX_EXT];
  _splitpath_s(szModuleFullPath.c_str(), drive, dir, fname, ext);
  szModuleName = fname;
  char moddir[MAX_PATH];
  _makepath_s(moddir, drive, dir, nullptr, nullptr);
  szModulePath = moddir;
}

#else  // !_WIN32

HANDLE CModuleInfo::getApplicationModule() { return 0; }

void CModuleInfo::init(HANDLE module) { this->module = module; }

#endif  // _WIN32

CModuleInfo::~CModuleInfo(void) {}
