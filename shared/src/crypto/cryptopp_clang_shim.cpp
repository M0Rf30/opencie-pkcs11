// SPDX-License-Identifier: LGPL-3.0-or-later
// Explicit template instantiations for CryptoPP allocator classes.
//
// When consuming a static libcryptopp.a built by GCC, Clang's strict
// 'extern template' handling prevents local instantiation of these
// template constructors that GCC emitted as weak COMDATs. This file
// provides the missing instantiations.
//
// This is only needed when compiling with Clang against a GCC-built
// Crypto++ static library. GCC-to-GCC builds work fine without it.

#ifdef __clang__
#include <cryptopp/secblock.h>
template class CryptoPP::AllocatorWithCleanup<unsigned char, false>;
#endif
