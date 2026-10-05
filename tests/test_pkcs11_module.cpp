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

  void* symbol(const char* name) const {
    return handle_ == nullptr ? nullptr : dlsym(handle_, name);
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
    CHECK(info.libraryVersion.major == OPENCIE_VERSION_MAJOR);
    CHECK(info.libraryVersion.minor == OPENCIE_VERSION_MINOR);
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

TEST_CASE("C_OpenSession rejects a NULL session pointer", "[pkcs11]") {
  ModuleHandle module;
  CK_FUNCTION_LIST_PTR fl = module.functionList();
  REQUIRE(fl != nullptr);
  REQUIRE(fl->C_Initialize(nullptr) == CKR_OK);

  CHECK(fl->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, nullptr) ==
        CKR_ARGUMENTS_BAD);

  CHECK(fl->C_Finalize(nullptr) == CKR_OK);
}

// The progress/completion callbacks of the cie_* extension API are optional.
// Each call below used to dereference the NULL callback unconditionally and
// crash; now it must run to completion (here: fail, there is no PC/SC
// service and no card) without ever invoking a callback.
TEST_CASE("cie_* functions accept NULL callbacks", "[cie][callbacks]") {
  ModuleHandle module;

  SECTION("cie_timestamp reports an unreadable input file") {
    using Fn = CK_RV (*)(const char*, const char*, const char*, const char*,
                         const char*, void*);
    auto fn = reinterpret_cast<Fn>(module.symbol("cie_timestamp"));
    REQUIRE(fn != nullptr);
    CHECK(fn("/nonexistent/opencie-input", "http://127.0.0.1:9/tsa", nullptr,
             nullptr, "/nonexistent/opencie-token.tst",
             nullptr) == CKR_DEVICE_ERROR);
  }

  SECTION("cie_enable") {
    using Fn = CK_RV (*)(const char*, const char*, int*, void*, void*);
    auto fn = reinterpret_cast<Fn>(module.symbol("cie_enable"));
    REQUIRE(fn != nullptr);
    CHECK(fn("", "12345678", nullptr, nullptr, nullptr) != CKR_OK);
  }

  SECTION("cie_change_pin") {
    using Fn = CK_RV (*)(const char*, const char*, int*, void*);
    auto fn = reinterpret_cast<Fn>(module.symbol("cie_change_pin"));
    REQUIRE(fn != nullptr);
    CHECK(fn("12345678", "87654321", nullptr, nullptr) != CKR_OK);
  }

  SECTION("cie_unblock_pin") {
    using Fn = CK_RV (*)(const char*, const char*, int*, void*);
    auto fn = reinterpret_cast<Fn>(module.symbol("cie_unblock_pin"));
    REQUIRE(fn != nullptr);
    CHECK(fn("12345678", "87654321", nullptr, nullptr) != CKR_OK);
  }

  SECTION("cie_sign") {
    using Fn = CK_RV (*)(const char*, const char*, const char*, const char*,
                         int, float, float, float, float, const unsigned char*,
                         int, const char*, void*, void*);
    auto fn = reinterpret_cast<Fn>(module.symbol("cie_sign"));
    REQUIRE(fn != nullptr);
    CHECK(fn("/nonexistent/in.pdf", "pdf", "12345678", "", 0, 0.f, 0.f, 0.f,
             0.f, nullptr, 0, "/nonexistent/out.pdf", nullptr,
             nullptr) != CKR_OK);
  }
}
