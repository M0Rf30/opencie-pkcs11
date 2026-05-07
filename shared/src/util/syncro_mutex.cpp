// SPDX-License-Identifier: LGPL-3.0-or-later

#include "syncro_mutex.h"

#include "util/util.h"

extern CLog Log;
#ifdef _WIN32
CSyncroMutex::CSyncroMutex(void) : hMutex(nullptr) {}
#else
CSyncroMutex::CSyncroMutex(void) {}
#endif

#ifdef _WIN32

void CSyncroMutex::Create(void) {
  hMutex = CreateMutex(nullptr, FALSE, nullptr);
  ER_ASSERT(hMutex != nullptr, "Error creating mutex");
}

void CSyncroMutex::Create(const char *szName) {
  hMutex = OpenMutex(SYNCHRONIZE, FALSE, szName);
  if (hMutex == nullptr) {
    HRESULT r = GetLastError();
    if (r == ERROR_FILE_NOT_FOUND) {
      SECURITY_ATTRIBUTES attr;
      SECURITY_DESCRIPTOR secDesc;
      PSID pSid;
      SID_IDENTIFIER_AUTHORITY worldSidAuth = SECURITY_WORLD_SID_AUTHORITY;
      AllocateAndInitializeSid(&worldSidAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0,
                               0, 0, 0, &pSid);

      DWORD dwACL = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
                    GetLengthSid(pSid);
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
      ER_ASSERT(hMutex != nullptr, "Error creating named mutex");
      FreeSid(pSid);
    } else {
      ER_ASSERT(FALSE, "Error creating mutex")
    }
  }
}

CSyncroMutex::~CSyncroMutex(void) {
  if (hMutex) CloseHandle(hMutex);
}

void CSyncroMutex::Lock() {
  DWORD res = WaitForSingleObject(hMutex, INFINITE);
  ER_ASSERT(res == S_OK || res == WAIT_ABANDONED, "Error releasing mutex");
}

void CSyncroMutex::Unlock() {
  if (!ReleaseMutex(hMutex)) {
    ER_ASSERT(FALSE, "Error releasing mutex")
  }
}

CSyncroLocker::CSyncroLocker(CSyncroMutex &mutex) {
  pMutex = &mutex;
  pMutex->Lock();
}

CSyncroLocker::~CSyncroLocker() {
  // cppcheck-suppress throwInNoexceptFunction
  pMutex->Unlock();
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
