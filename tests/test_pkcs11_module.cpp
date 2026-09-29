// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later

// Black-box tests that load the built libopencie-pkcs11 module with dlopen(),
// the way NSS, p11-kit and pkcs11-tool do. Run by Meson with
// OPENCIE_MODULE=<module path> and PCSCLITE_CSOCK_NAME pointing at a socket
// that does not exist, so pcsc-lite reports SCARD_E_NO_SERVICE exactly as
// when pcscd is not running.

#include <dlfcn.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdlib>

#include "pkcs11/cryptoki.h"

namespace {

class ModuleHandle {
 public:
  ModuleHandle() {
    const char* path = std::getenv("OPENCIE_MODULE");
    // RTLD_NODELETE: the module keeps its logger in a deliberately leaked
    // static singleton; unmapping it on dlclose() would make LeakSanitizer
    // report that allocation as a direct leak.
    if (path != nullptr)
      handle_ = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
  }
  ~ModuleHandle() {
    if (handle_ != nullptr) dlclose(handle_);
  }
  ModuleHandle(const ModuleHandle&) = delete;
  ModuleHandle& operator=(const ModuleHandle&) = delete;

  CK_FUNCTION_LIST_PTR functionList() const {
    if (handle_ == nullptr) return nullptr;
    auto getFunctionList = reinterpret_cast<CK_C_GetFunctionList>(
        dlsym(handle_, "C_GetFunctionList"));
    CK_FUNCTION_LIST_PTR fl = nullptr;
    if (getFunctionList == nullptr || getFunctionList(&fl) != CKR_OK)
      return nullptr;
    return fl;
  }

 private:
  void* handle_ = nullptr;
};

}  // namespace

TEST_CASE("Module initializes without a PC/SC service", "[pkcs11][nss]") {
  ModuleHandle module;
  CK_FUNCTION_LIST_PTR fl = module.functionList();
  REQUIRE(fl != nullptr);

  // Same arguments NSS passes (observed with modutil and pkcs11-spy).
  CK_C_INITIALIZE_ARGS args {};
  args.flags = CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS;
  REQUIRE(fl->C_Initialize(&args) == CKR_OK);

  SECTION("no slots are reported") {
    CK_ULONG count = 42;
    CHECK(fl->C_GetSlotList(CK_FALSE, nullptr, &count) == CKR_OK);
    CHECK(count == 0);
    count = 42;
    CHECK(fl->C_GetSlotList(CK_TRUE, nullptr, &count) == CKR_OK);
    CHECK(count == 0);
  }

  SECTION("C_GetInfo matches the function list version") {
    CK_INFO info {};
    REQUIRE(fl->C_GetInfo(&info) == CKR_OK);
    CHECK(info.cryptokiVersion.major == fl->version.major);
    CHECK(info.cryptokiVersion.minor == fl->version.minor);
    CHECK(info.cryptokiVersion.major == 2);
    CHECK(info.cryptokiVersion.minor == 40);
  }

  CHECK(fl->C_Finalize(nullptr) == CKR_OK);
}

TEST_CASE("Module can be re-initialized without a PC/SC service",
          "[pkcs11][nss]") {
  ModuleHandle module;
  CK_FUNCTION_LIST_PTR fl = module.functionList();
  REQUIRE(fl != nullptr);

  for (int i = 0; i < 2; ++i) {
    REQUIRE(fl->C_Initialize(nullptr) == CKR_OK);
    CHECK(fl->C_Initialize(nullptr) == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    REQUIRE(fl->C_Finalize(nullptr) == CKR_OK);
  }
}
