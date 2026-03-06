// SPDX-License-Identifier: LGPL-3.0-or-later

#include "syncro_mutex.h"

#include "util/util.h"

extern CLog Log;
CSyncroMutex::CSyncroMutex(void) { hMutex = nullptr; }

#ifdef _WIN32

void CSyncroMutex::Create(void) {
  init_func
  hMutex = CreateMutex(nullptr, FALSE, nullptr);
  ER_ASSERT(hMutex != nullptr, "Errore nella creazione del Mutex");
  exit_func
}

void CSyncroMutex::Create(const char *szName) {
  init_func
  hMutex = OpenMutex(SYNCHRONIZE, FALSE, szName);
  if (hMutex == nullptr) {
    HRESULT r = GetLastError();
    if (r == ERROR_FILE_NOT_FOUND) {
      SECURITY_ATTRIBUTES attr;
      SECURITY_DESCRIPTOR secDesc;
      PSID pSid;
      SID_IDENTIFIER_AUTHORITY worldSidAuth = SECURITY_WORLD_SID_AUTHORITY;
      AllocateAndInitializeSid(&worldSidAuth, 1, SECURITY_WORLD_RID, 0, 0, 0,
                               0, 0, 0, 0, &pSid);

      DWORD dwACL = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(pSid);
      ByteDynArray pbtACL(dwACL);
      PACL pACL = (PACL)pbtACL.data();

      InitializeAcl(pACL, dwACL, ACL_REVISION);

      AddAccessAllowedAceEx(pACL, ACL_REVISION, INHERITED_ACE, SYNCHRONIZE,
                            pSid);

      InitializeSecurityDescriptor(&secDesc, SECURITY_DESCRIPTOR_REVISION);
      SetSecurityDescriptorDacl(&secDesc, TRUE, pACL, FALSE);

      attr.bInheritHandle = FALSE;
      attr.lpSecurityDescriptor = &secDesc;

      hMutex = CreateMutex(&attr, FALSE, szName);
      ER_ASSERT(hMutex != nullptr,
                "Errore nella creazione del Mutex con nome");
      FreeSid(pSid);
    } else {
      ER_ASSERT(FALSE, "Errore nella creazione del Mutex")
    }
  }
  exit_func
}

CSyncroMutex::~CSyncroMutex(void) {
  init_func
  if (hMutex) CloseHandle(hMutex);
  exit_func
}

void CSyncroMutex::Lock() {
  init_func
  DWORD res = WaitForSingleObject(hMutex, INFINITE);
  ER_ASSERT(res == S_OK || res == WAIT_ABANDONED,
            "Errore nel rilascio del mutex");
  exit_func
}

void CSyncroMutex::Unlock() {
  init_func
  if (!ReleaseMutex(hMutex)) {
    ER_ASSERT(FALSE, "Errore nel rilascio del mutex")
  }
  exit_func
}

CSyncroLocker::CSyncroLocker(CSyncroMutex &mutex) {
  init_func
  pMutex = &mutex;
  pMutex->Lock();
  exit_func
}

CSyncroLocker::~CSyncroLocker() {
  init_func
  pMutex->Unlock();
  exit_func
}

#else  // !_WIN32

void CSyncroMutex::Create(void) {}

void CSyncroMutex::Create(const char * /*szName*/) {}

CSyncroMutex::~CSyncroMutex(void) {}

void CSyncroMutex::Lock() {}

void CSyncroMutex::Unlock() {}

CSyncroLocker::CSyncroLocker(CSyncroMutex &mutex) { pMutex = &mutex; }

CSyncroLocker::~CSyncroLocker() {}

#endif  // _WIN32
