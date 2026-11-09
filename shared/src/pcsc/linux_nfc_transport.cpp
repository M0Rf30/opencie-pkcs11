// SPDX-FileCopyrightText: 2026 Gianluca Boiano
// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * linux_nfc_transport.cpp — Linux kernel NFC backend implementation.
 *
 * Maps ISmartCardTransport operations onto the kernel NFC subsystem:
 *
 *   EstablishContext  →  open generic netlink socket, resolve family "nfc"
 *   ListReaders       →  "NFC\0\0" when an NFC device exists
 *   GetStatusChange   →  poll for an ISO-DEP target (card presence)
 *   Connect           →  AF_NFC/NFC_SOCKPROTO_RAW socket connected to target
 *   Transmit          →  send()/recv() of ISO-DEP APDUs
 *   Disconnect        →  close the data socket (deactivates the target)
 *   GetAttrib         →  synthetic ATR built from the target's ATS
 *   Begin/EndTransaction → no-ops (the socket owner has exclusive access)
 *
 * Both ISO 14443 type A and type B are polled: the CIE chip families in the
 * field (NXP, Gemalto, STM) are not all the same technology, and the data
 * socket must be opened with the protocol the target was activated with.
 */

#include "pcsc/linux_nfc_transport.h"

#if defined(__linux__) && !defined(__ANDROID__)

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <thread>

#include "logger/logger.h"

using namespace CieIDLogger;

/* Kernel NFC does not expose AF_NFC through <sys/socket.h> on every libc. */
#ifndef AF_NFC
#define AF_NFC 39
#endif
#ifndef PF_NFC
#define PF_NFC AF_NFC
#endif

namespace {

constexpr size_t kNlBuf = 8192;

/* Largest ISO-DEP response we accept in one read (extended APDU + SW). */
constexpr size_t kMaxApduResponse = 65536 + 2;

/* SCARD_ATTR_ATR_STRING lives in <PCSC/reader.h>, which this backend does
 * not otherwise need; the value is fixed by the PC/SC specification. */
constexpr DWORD kAtrStringAttr = ((9u << 16) | 0x0303u);

/* NFC_ATTR_TARGET_ATS is an enumerator, not a macro, so it cannot be probed
 * with #ifdef, and uapi headers older than Linux 6.9 (Ubuntu 24.04 ships
 * 6.8) do not name it at all. Its value is fixed by the netlink ABI as the
 * entry right after NFC_ATTR_VENDOR_DATA, so derive it instead of requiring
 * a header that names it. */
constexpr uint16_t kAttrTargetAts = NFC_ATTR_VENDOR_DATA + 1;

struct NlRequest {
  struct nlmsghdr hdr;
  struct genlmsghdr genl;
  char payload[512];
};

/** Appends one netlink attribute to a generic netlink request. */
bool putAttr(NlRequest *req, uint16_t type, const void *data, uint16_t len) {
  struct nlattr attr {};
  attr.nla_type = type;
  attr.nla_len = static_cast<uint16_t>(NLA_HDRLEN + len);

  const size_t offset = NLMSG_ALIGN(req->hdr.nlmsg_len);
  if (offset + NLA_ALIGN(attr.nla_len) > sizeof(NlRequest)) return false;

  char *base = reinterpret_cast<char *>(req) + offset;
  memcpy(base, &attr, sizeof(attr));
  memcpy(base + NLA_HDRLEN, data, len);
  req->hdr.nlmsg_len = static_cast<uint32_t>(offset + NLA_ALIGN(attr.nla_len));
  return true;
}

bool putU32(NlRequest *req, uint16_t type, uint32_t value) {
  return putAttr(req, type, &value, sizeof(value));
}

const void *attrData(const struct nlattr *attr) {
  return reinterpret_cast<const char *>(attr) + NLA_HDRLEN;
}

uint16_t attrLen(const struct nlattr *attr) {
  return static_cast<uint16_t>(attr->nla_len - NLA_HDRLEN);
}

uint32_t attrU32(const struct nlattr *attr) {
  uint32_t value = 0;
  if (attrLen(attr) >= sizeof(value))
    memcpy(&value, attrData(attr), sizeof(value));
  return value;
}

/** Walks a run of netlink attributes starting at @p base. */
template <typename Fn>
void forEachAttrIn(const char *base, int len, Fn &&fn) {
  const struct nlattr *attr = reinterpret_cast<const struct nlattr *>(base);
  while (len >= static_cast<int>(NLA_HDRLEN) && attr->nla_len >= NLA_HDRLEN &&
         attr->nla_len <= len) {
    fn(attr);
    const int step = NLA_ALIGN(attr->nla_len);
    len -= step;
    attr = reinterpret_cast<const struct nlattr *>(
        reinterpret_cast<const char *>(attr) + step);
  }
}

/** Walks the attributes of one generic netlink message. */
template <typename Fn>
void forEachAttr(const struct nlmsghdr *nlh, Fn &&fn) {
  const int len = static_cast<int>(nlh->nlmsg_len) -
                  static_cast<int>(NLMSG_HDRLEN + GENL_HDRLEN);
  if (len <= 0) return;
  forEachAttrIn(
      reinterpret_cast<const char *>(nlh) + NLMSG_HDRLEN + GENL_HDRLEN, len,
      std::forward<Fn>(fn));
}

}  // namespace

std::vector<uint8_t> linuxNfcAtrFromAts(const uint8_t *ats, size_t len) {
  /* ATS layout: TL, T0, [TA(1)], [TB(1)], [TC(1)], historical bytes.
   * T0 bits 4-6 flag which interface bytes are present. */
  size_t offset = len;
  if (ats && len >= 2) {
    offset = 2;
    const uint8_t t0 = ats[1];
    if (t0 & 0x10) ++offset; /* TA(1) */
    if (t0 & 0x20) ++offset; /* TB(1) */
    if (t0 & 0x40) ++offset; /* TC(1) */
  }

  if (!ats || offset >= len) {
    /* No historical bytes (type B targets, mostly): minimal ATR. */
    return {0x3B, 0x80, 0x80, 0x01, 0x01};
  }

  /* ISO 7816-3 T0 carries the historical byte count in 4 bits: cap at 15 so
   * T0 always agrees with the bytes that follow (an ATS can carry more, and
   * an inconsistent ATR would be mis-parsed by the template matcher). */
  const size_t histLen = std::min<size_t>(len - offset, 15);
  std::vector<uint8_t> atr {0x3B, static_cast<uint8_t>(0x80 | (histLen & 0x0F)),
                            0x80, 0x01};
  atr.insert(atr.end(), ats + offset, ats + offset + histLen);

  uint8_t tck = 0;
  for (size_t i = 1; i < atr.size(); ++i) tck ^= atr[i];
  atr.push_back(tck);
  return atr;
}

LinuxNFCTransport::LinuxNFCTransport() = default;

LinuxNFCTransport::~LinuxNFCTransport() {
  closeDataSocket();
  if (netlinkFd_ >= 0) close(netlinkFd_);
}

/* ===== netlink plumbing ===== */

bool LinuxNFCTransport::ensureNetlink() {
  if (netlinkFd_ >= 0 && familyId_ != 0) return true;

  if (netlinkFd_ < 0) {
    netlinkFd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (netlinkFd_ < 0) return false;

    struct sockaddr_nl local {};
    local.nl_family = AF_NETLINK;
    if (bind(netlinkFd_, reinterpret_cast<struct sockaddr *>(&local),
             sizeof(local)) < 0) {
      close(netlinkFd_);
      netlinkFd_ = -1;
      return false;
    }
  }

  /* Resolve the "nfc" generic netlink family and its event multicast group. */
  NlRequest req {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.hdr.nlmsg_type = GENL_ID_CTRL;
  req.hdr.nlmsg_flags = NLM_F_REQUEST;
  req.hdr.nlmsg_seq = ++sequence_;
  req.genl.cmd = CTRL_CMD_GETFAMILY;
  req.genl.version = 1;
  if (!putAttr(&req, CTRL_ATTR_FAMILY_NAME, NFC_GENL_NAME,
               static_cast<uint16_t>(strlen(NFC_GENL_NAME) + 1)))
    return false;

  if (send(netlinkFd_, &req, req.hdr.nlmsg_len, 0) < 0) return false;

  char buf[kNlBuf];
  const ssize_t received = recv(netlinkFd_, buf, sizeof(buf), 0);
  if (received <= 0) return false;

  const struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
  if (nlh->nlmsg_type == NLMSG_ERROR) return false;

  forEachAttr(nlh, [&](const struct nlattr *attr) {
    if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
      uint16_t id = 0;
      if (attrLen(attr) >= sizeof(id)) memcpy(&id, attrData(attr), sizeof(id));
      familyId_ = id;
      return;
    }
    if (attr->nla_type != CTRL_ATTR_MCAST_GROUPS) return;

    /* Nested: each group carries CTRL_ATTR_MCAST_GRP_NAME/_ID. */
    forEachAttrIn(reinterpret_cast<const char *>(attrData(attr)), attrLen(attr),
                  [&](const struct nlattr *group) {
                    const char *name = nullptr;
                    uint32_t id = 0;
                    forEachAttrIn(
                        reinterpret_cast<const char *>(attrData(group)),
                        attrLen(group), [&](const struct nlattr *inner) {
                          if (inner->nla_type == CTRL_ATTR_MCAST_GRP_NAME)
                            name =
                                reinterpret_cast<const char *>(attrData(inner));
                          else if (inner->nla_type == CTRL_ATTR_MCAST_GRP_ID)
                            id = attrU32(inner);
                        });
                    if (name && strcmp(name, NFC_GENL_MCAST_EVENT_NAME) == 0)
                      eventGroup_ = id;
                  });
  });

  if (familyId_ == 0) {
    static std::atomic<bool> logged {false};
    if (!logged.exchange(true))
      LOG_ERROR(
          "LinuxNFCTransport - generic netlink family \"nfc\" not found: the "
          "kernel NFC subsystem is not available (nfc module not loaded?)");
    return false;
  }

  if (eventGroup_ != 0) {
    setsockopt(netlinkFd_, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &eventGroup_,
               sizeof(eventGroup_));
  }
  return true;
}

bool LinuxNFCTransport::findDevice(uint32_t *deviceIndex) {
  if (!ensureNetlink()) return false;

  NlRequest req {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.hdr.nlmsg_type = familyId_;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = ++sequence_;
  req.genl.cmd = NFC_CMD_GET_DEVICE;
  req.genl.version = NFC_GENL_VERSION;

  if (send(netlinkFd_, &req, req.hdr.nlmsg_len, 0) < 0) return false;

  char buf[kNlBuf];
  ssize_t received = recv(netlinkFd_, buf, sizeof(buf), 0);
  if (received <= 0) return false;

  bool found = false;
  int kernelError = 0;
  for (struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
       NLMSG_OK(nlh, static_cast<unsigned int>(received)) && !found;
       nlh = NLMSG_NEXT(nlh, received)) {
    if (nlh->nlmsg_type == NLMSG_DONE) break;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
      kernelError =
          static_cast<const struct nlmsgerr *>(NLMSG_DATA(nlh))->error;
      break;
    }
    forEachAttr(nlh, [&](const struct nlattr *attr) {
      if (!found && attr->nla_type == NFC_ATTR_DEVICE_INDEX) {
        *deviceIndex = attrU32(attr);
        found = true;
      }
    });
  }
  if (!found) {
    static std::atomic<bool> logged {false};
    if (!logged.exchange(true)) {
      if (kernelError == -EPERM)
        LOG_ERROR(
            "LinuxNFCTransport - NFC_CMD_GET_DEVICE denied (EPERM): the "
            "kernel requires CAP_NET_ADMIN for NFC netlink commands");
      else if (kernelError != 0)
        LOG_ERROR("LinuxNFCTransport - NFC_CMD_GET_DEVICE failed: %s",
                  strerror(-kernelError));
      else
        LOG_ERROR("LinuxNFCTransport - no kernel NFC device found");
    }
  }
  return found;
}

int LinuxNFCTransport::awaitAck(uint32_t seq) {
  /* NLM_F_ACK requests get an NLMSG_ERROR reply (error 0 on success). It must
   * be consumed here: left in the queue it would be read later as the reply
   * to GET_TARGET, and a present card would look absent. Multicast events
   * interleaved on the same socket are skipped. */
  for (int attempt = 0; attempt < 8; ++attempt) {
    struct pollfd pfd {netlinkFd_, POLLIN, 0};
    if (poll(&pfd, 1, 1000) <= 0) return -ETIMEDOUT;

    char buf[kNlBuf];
    ssize_t received = recv(netlinkFd_, buf, sizeof(buf), 0);
    if (received <= 0) return -EIO;

    for (struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         NLMSG_OK(nlh, static_cast<unsigned int>(received));
         nlh = NLMSG_NEXT(nlh, received)) {
      if (nlh->nlmsg_type != NLMSG_ERROR || nlh->nlmsg_seq != seq) continue;
      const struct nlmsgerr *err =
          static_cast<const struct nlmsgerr *>(NLMSG_DATA(nlh));
      return err->error;
    }
  }
  return -ETIMEDOUT;
}

int LinuxNFCTransport::sendDeviceCmd(uint8_t cmd, uint32_t deviceIndex,
                                     bool withProtocols) {
  NlRequest req {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.hdr.nlmsg_type = familyId_;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = ++sequence_;
  req.genl.cmd = cmd;
  req.genl.version = NFC_GENL_VERSION;
  if (!putU32(&req, NFC_ATTR_DEVICE_INDEX, deviceIndex)) return -EINVAL;
  /* CIE chips ship as both ISO 14443 type A and type B; poll for both. */
  if (withProtocols &&
      !putU32(&req, NFC_ATTR_PROTOCOLS,
              NFC_PROTO_ISO14443_MASK | NFC_PROTO_ISO14443_B_MASK))
    return -EINVAL;
  if (send(netlinkFd_, &req, req.hdr.nlmsg_len, 0) <= 0) return -errno;
  return awaitAck(req.hdr.nlmsg_seq);
}

bool LinuxNFCTransport::powerUpAndPoll(uint32_t deviceIndex) {
  if (!ensureNetlink()) return false;

  auto sendCmd = [&](uint8_t cmd, bool withProtocols) -> int {
    return sendDeviceCmd(cmd, deviceIndex, withProtocols);
  };

  /* An already-powered device answers DEV_UP with -EALREADY: fine. */
  const int up = sendCmd(NFC_CMD_DEV_UP, false);
  if (up != 0 && up != -EALREADY)
    LOG_ERROR("LinuxNFCTransport - DEV_UP on nfc%u failed: %s", deviceIndex,
              strerror(-up));

  const int pollRv = sendCmd(NFC_CMD_START_POLL, true);
  if (pollRv == -EBUSY) {
    /* Another client (typically neard) already owns the poll loop. Targets it
     * activates are still listed by GET_TARGET, so carry on rather than fail;
     * but neard may deactivate the target under us, so say so. */
    LOG_INFO(
        "LinuxNFCTransport - nfc%u is already polling (neard running?); "
        "reusing its poll loop. Stop neard if card access is unreliable.",
        deviceIndex);
  } else if (pollRv != 0) {
    LOG_ERROR("LinuxNFCTransport - START_POLL on nfc%u failed: %s", deviceIndex,
              strerror(-pollRv));
    return false;
  }

  polling_ = true;
  return true;
}

bool LinuxNFCTransport::queryTarget(uint32_t deviceIndex, Target *target) {
  if (!ensureNetlink()) return false;

  /* Ask the kernel for the currently activated targets. */
  NlRequest req {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req.hdr.nlmsg_type = familyId_;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = ++sequence_;
  req.genl.cmd = NFC_CMD_GET_TARGET;
  req.genl.version = NFC_GENL_VERSION;
  if (!putU32(&req, NFC_ATTR_DEVICE_INDEX, deviceIndex)) return false;
  if (send(netlinkFd_, &req, req.hdr.nlmsg_len, 0) <= 0) return false;

  /* Consume the whole dump (up to NLMSG_DONE), skipping multicast events and
   * stale replies, so nothing is left queued for the next request. */
  bool found = false;
  for (int attempt = 0; attempt < 8; ++attempt) {
    struct pollfd pfd {netlinkFd_, POLLIN, 0};
    if (poll(&pfd, 1, 1000) <= 0) break;

    char buf[kNlBuf];
    ssize_t received = recv(netlinkFd_, buf, sizeof(buf), 0);
    if (received <= 0) break;

    for (struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         NLMSG_OK(nlh, static_cast<unsigned int>(received));
         nlh = NLMSG_NEXT(nlh, received)) {
      if (nlh->nlmsg_seq != req.hdr.nlmsg_seq) continue;
      if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR)
        return found;

      bool haveIndex = false;
      Target candidate;
      candidate.deviceIndex = deviceIndex;
      forEachAttr(nlh, [&](const struct nlattr *attr) {
        switch (attr->nla_type) {
          case NFC_ATTR_TARGET_INDEX:
            candidate.targetIndex = attrU32(attr);
            haveIndex = true;
            break;
          case kAttrTargetAts: {
            const uint8_t *ats = static_cast<const uint8_t *>(attrData(attr));
            candidate.ats.assign(ats, ats + attrLen(attr));
            break;
          }
          case NFC_ATTR_TARGET_SENSB_RES:
            /* Only type B targets carry SENSB_RES. */
            candidate.protocol = NFC_PROTO_ISO14443_B;
            break;
          default:
            break;
        }
      });

      if (haveIndex && !found) {
        if (candidate.protocol == 0) candidate.protocol = NFC_PROTO_ISO14443;
        *target = candidate;
        found = true;
      }
    }
  }
  return found;
}

bool LinuxNFCTransport::waitForTarget(uint32_t deviceIndex, DWORD timeoutMs,
                                      Target *target) {
  /* Real elapsed time, not a count of iterations: queryTarget() can return
   * at once, so counting slices would end the wait early. */
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  constexpr auto kSlice = std::chrono::milliseconds(200);

  while (!cancelled_.load(std::memory_order_relaxed)) {
    if (queryTarget(deviceIndex, target)) return true;
    if (timeoutMs != INFINITE && std::chrono::steady_clock::now() >= deadline)
      return false;
    std::this_thread::sleep_for(kSlice);
  }
  return false;
}

/* ===== data socket ===== */

bool LinuxNFCTransport::openDataSocket(const Target &target) {
  closeDataSocket();

  dataFd_ = socket(PF_NFC, SOCK_SEQPACKET | SOCK_CLOEXEC, NFC_SOCKPROTO_RAW);
  if (dataFd_ < 0) return false;

  struct sockaddr_nfc addr {};
  addr.sa_family = AF_NFC;
  addr.dev_idx = target.deviceIndex;
  addr.target_idx = target.targetIndex;
  addr.nfc_protocol = target.protocol;

  if (connect(dataFd_, reinterpret_cast<struct sockaddr *>(&addr),
              sizeof(addr)) < 0) {
    LOG_ERROR(
        "LinuxNFCTransport - connect to nfc%u target %u (ISO 14443 type %c) "
        "failed: %s",
        target.deviceIndex, target.targetIndex,
        target.protocol == NFC_PROTO_ISO14443_B ? 'B' : 'A', strerror(errno));
    close(dataFd_);
    dataFd_ = -1;
    return false;
  }
  LOG_INFO(
      "LinuxNFCTransport - connected to nfc%u target %u (ISO 14443 type %c, "
      "%zu ATS bytes)",
      target.deviceIndex, target.targetIndex,
      target.protocol == NFC_PROTO_ISO14443_B ? 'B' : 'A', target.ats.size());
  if (target.ats.empty())
    LOG_INFO(
        "LinuxNFCTransport - kernel reported no ATS for this target; the "
        "synthetic ATR carries no historical bytes, so CIE chip type "
        "detection cannot use it");
  return true;
}

void LinuxNFCTransport::closeDataSocket() {
  if (dataFd_ >= 0) {
    close(dataFd_);
    dataFd_ = -1;
  }
}

void LinuxNFCTransport::buildATR(const Target &target) {
  /* Contactless cards have no ATR. Synthesize one from the ATS historical
   * bytes exactly like the Android backend does, so the card-template
   * matching in CSlot keeps recognizing the NXP/Gemalto/STM CIE chips. */
  cachedATR_ = linuxNfcAtrFromAts(target.ats.data(), target.ats.size());
}

/* ===== ISmartCardTransport ===== */

LONG LinuxNFCTransport::EstablishContext(DWORD /*dwScope*/,
                                         LPSCARDCONTEXT phContext) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!ensureNetlink()) return SCARD_E_NO_SERVICE;
  cancelled_.store(false, std::memory_order_relaxed);
  if (phContext) *phContext = kContext;
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::ReleaseContext(SCARDCONTEXT /*hContext*/) {
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::IsValidContext(SCARDCONTEXT hContext) {
  return hContext == kContext ? SCARD_S_SUCCESS : SCARD_E_INVALID_HANDLE;
}

LONG LinuxNFCTransport::ListReaders(SCARDCONTEXT /*hContext*/, LPSTR mszReaders,
                                    LPDWORD pcchReaders) {
  if (!pcchReaders) return SCARD_E_INVALID_PARAMETER;

  std::lock_guard<std::mutex> lock(mutex_);
  uint32_t deviceIndex = 0;
  if (!findDevice(&deviceIndex)) {
    *pcchReaders = 0;
    return SCARD_E_NO_READERS_AVAILABLE;
  }

  /* Multi-string: "NFC\0\0" — one reader named "NFC", double-NUL terminated. */
  static const char kReaderName[] = "NFC";
  const DWORD needed = sizeof(kReaderName) + 1;

  if (!mszReaders) {
    *pcchReaders = needed;
    return SCARD_S_SUCCESS;
  }
  if (*pcchReaders < needed) {
    *pcchReaders = needed;
    return SCARD_E_INSUFFICIENT_BUFFER;
  }
  memcpy(mszReaders, kReaderName, sizeof(kReaderName));
  mszReaders[sizeof(kReaderName)] = '\0';
  *pcchReaders = needed;
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::GetStatusChange(SCARDCONTEXT /*hContext*/,
                                        DWORD dwTimeout,
                                        SCARD_READERSTATE *rgReaderStates,
                                        DWORD cReaders) {
  if (!rgReaderStates || cReaders == 0) return SCARD_E_INVALID_PARAMETER;

  /* PC/SC semantics: return as soon as a reader's state differs from the
   * caller's dwCurrentState; otherwise block up to dwTimeout and report
   * SCARD_E_TIMEOUT with no CHANGED flag. mutex_ is held only for one probe
   * at a time, never while waiting, so Connect/Transmit/Cancel from other
   * threads are not stalled behind a long poll. */
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(dwTimeout);
  constexpr auto kSlice = std::chrono::milliseconds(200);

  for (;;) {
    if (cancelled_.load(std::memory_order_relaxed)) return SCARD_E_CANCELLED;

    bool present = false;
    std::vector<uint8_t> atr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      uint32_t deviceIndex = 0;
      if (!findDevice(&deviceIndex)) return SCARD_E_NO_READERS_AVAILABLE;
      if (!polling_ && !powerUpAndPoll(deviceIndex)) return SCARD_E_NO_SERVICE;

      Target target;
      present = queryTarget(deviceIndex, &target);
      if (present) {
        target_ = target;
        hasTarget_ = true;
        buildATR(target_);
        atr = cachedATR_;
      } else {
        hasTarget_ = false;
      }
    }

    const DWORD state = present ? SCARD_STATE_PRESENT : SCARD_STATE_EMPTY;
    bool changed = false;
    for (DWORD i = 0; i < cReaders; ++i) {
      if (rgReaderStates[i].dwCurrentState & SCARD_STATE_IGNORE) continue;
      if ((rgReaderStates[i].dwCurrentState & state) == 0) changed = true;
    }

    const bool timedOut =
        dwTimeout != INFINITE && std::chrono::steady_clock::now() >= deadline;
    if (changed || timedOut) {
      for (DWORD i = 0; i < cReaders; ++i) {
        rgReaderStates[i].dwEventState = state;
        if ((rgReaderStates[i].dwCurrentState & state) == 0)
          rgReaderStates[i].dwEventState |= SCARD_STATE_CHANGED;

        const DWORD atrLen =
            std::min(static_cast<DWORD>(atr.size()),
                     static_cast<DWORD>(sizeof(rgReaderStates[i].rgbAtr)));
        if (atrLen) memcpy(rgReaderStates[i].rgbAtr, atr.data(), atrLen);
        rgReaderStates[i].cbAtr = atrLen;
      }
      return changed ? SCARD_S_SUCCESS : SCARD_E_TIMEOUT;
    }

    /* Nothing changed: sleep without holding mutex_, woken early by Cancel().
     */
    std::unique_lock<std::mutex> waitLock(waitMutex_);
    waitCv_.wait_for(waitLock, kSlice, [this] {
      return cancelled_.load(std::memory_order_relaxed);
    });
  }
}

LONG LinuxNFCTransport::Cancel(SCARDCONTEXT /*hContext*/) {
  {
    /* Taking waitMutex_ orders the store against a waiter's predicate check,
     * so the wake-up cannot be lost. */
    std::lock_guard<std::mutex> lock(waitMutex_);
    cancelled_.store(true, std::memory_order_relaxed);
  }
  waitCv_.notify_all();
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::Connect(SCARDCONTEXT /*hContext*/, LPCSTR /*szReader*/,
                                DWORD /*dwShareMode*/,
                                DWORD /*dwPreferredProtocols*/,
                                LPSCARDHANDLE phCard,
                                LPDWORD pdwActiveProtocol) {
  std::lock_guard<std::mutex> lock(mutex_);

  uint32_t deviceIndex = 0;
  if (!findDevice(&deviceIndex)) return SCARD_E_NO_READERS_AVAILABLE;
  if (!polling_ && !powerUpAndPoll(deviceIndex)) return SCARD_E_NO_SERVICE;

  Target target = target_;
  if (!hasTarget_ && !waitForTarget(deviceIndex, 2000, &target))
    return SCARD_W_REMOVED_CARD;

  if (!openDataSocket(target)) return SCARD_E_NOT_TRANSACTED;

  target_ = target;
  hasTarget_ = true;
  buildATR(target);
  if (phCard) *phCard = kHandle;
  if (pdwActiveProtocol) *pdwActiveProtocol = SCARD_PROTOCOL_T1;
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::Disconnect(SCARDHANDLE /*hCard*/,
                                   DWORD /*dwDisposition*/) {
  std::lock_guard<std::mutex> lock(mutex_);
  closeDataSocket();
  hasTarget_ = false;
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::Reconnect(SCARDHANDLE /*hCard*/, DWORD /*dwShareMode*/,
                                  DWORD /*dwPreferredProtocols*/,
                                  DWORD dwInitialization,
                                  LPDWORD pdwActiveProtocol) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!hasTarget_) return SCARD_W_REMOVED_CARD;

  closeDataSocket();

  if (dwInitialization == SCARD_RESET_CARD ||
      dwInitialization == SCARD_UNPOWER_CARD) {
    /* A contactless target has no reset line and the kernel NFC API offers
     * no RF field power-cycle. The closest equivalent is to stop the poll
     * loop, which deactivates the target (ISO-DEP DESELECT), then poll again
     * so the card is re-activated from its idle state, and to re-read the
     * ATS so the synthetic ATR describes the new activation. Card-side
     * session state (secure messaging, PIN verification) is thereby dropped
     * like after a PC/SC reset. If another client (neard) owns the poll loop
     * we cannot deactivate the target; the connection is then only reopened
     * and the caller must not assume the card was reset. */
    uint32_t deviceIndex = target_.deviceIndex;
    const int stopRv = sendDeviceCmd(NFC_CMD_STOP_POLL, deviceIndex, false);
    polling_ = false;
    hasTarget_ = false;
    if (stopRv != 0)
      LOG_INFO(
          "LinuxNFCTransport - STOP_POLL on nfc%u failed (%s): card was not "
          "power-cycled",
          deviceIndex, strerror(-stopRv));
    if (!powerUpAndPoll(deviceIndex)) return SCARD_E_NO_SERVICE;

    Target target;
    if (!waitForTarget(deviceIndex, 2000, &target)) return SCARD_W_REMOVED_CARD;
    target_ = target;
    hasTarget_ = true;
  }

  if (!openDataSocket(target_)) return SCARD_W_REMOVED_CARD;
  buildATR(target_);
  if (pdwActiveProtocol) *pdwActiveProtocol = SCARD_PROTOCOL_T1;
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::Transmit(SCARDHANDLE /*hCard*/,
                                 const SCARD_IO_REQUEST * /*pioSendPci*/,
                                 LPCBYTE pbSendBuffer, DWORD cbSendLength,
                                 LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
  if (!pbSendBuffer || !pbRecvBuffer || !pcbRecvLength)
    return SCARD_E_INVALID_PARAMETER;

  std::lock_guard<std::mutex> lock(mutex_);
  if (dataFd_ < 0) return SCARD_E_INVALID_HANDLE;

  if (send(dataFd_, pbSendBuffer, cbSendLength, 0) < 0)
    return SCARD_E_NOT_TRANSACTED;

  /* Kernel raw sockets prefix every response with a NFC_HEADER_SIZE NULL
   * header so that genuinely empty responses stay distinguishable. The read
   * buffer is sized for the largest ISO-DEP response, not for the caller's
   * buffer: SOCK_SEQPACKET discards whatever does not fit in one read, and a
   * silently truncated APDU response would be far worse than a clean
   * SCARD_E_INSUFFICIENT_BUFFER. */
  std::vector<uint8_t> buffer(kMaxApduResponse + NFC_HEADER_SIZE);
  const ssize_t received = recv(dataFd_, buffer.data(), buffer.size(), 0);
  if (received < NFC_HEADER_SIZE) {
    closeDataSocket();
    hasTarget_ = false;
    return SCARD_E_NOT_TRANSACTED;
  }

  const size_t payload = static_cast<size_t>(received) - NFC_HEADER_SIZE;
  if (payload > *pcbRecvLength) {
    *pcbRecvLength = static_cast<DWORD>(payload);
    return SCARD_E_INSUFFICIENT_BUFFER;
  }
  memcpy(pbRecvBuffer, buffer.data() + NFC_HEADER_SIZE, payload);
  *pcbRecvLength = static_cast<DWORD>(payload);
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::BeginTransaction(SCARDHANDLE /*hCard*/) {
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::EndTransaction(SCARDHANDLE /*hCard*/,
                                       DWORD /*dwDisposition*/) {
  return SCARD_S_SUCCESS;
}

LONG LinuxNFCTransport::GetAttrib(SCARDHANDLE /*hCard*/, DWORD dwAttrId,
                                  LPBYTE pbAttr, LPDWORD pcbAttrLen) {
  if (dwAttrId != kAtrStringAttr) return SCARD_E_INVALID_PARAMETER;
  if (!pcbAttrLen) return SCARD_E_INVALID_PARAMETER;

  std::lock_guard<std::mutex> lock(mutex_);
  if (cachedATR_.empty()) buildATR(target_);

  const DWORD needed = static_cast<DWORD>(cachedATR_.size());
  if (!pbAttr) {
    *pcbAttrLen = needed;
    return SCARD_S_SUCCESS;
  }
  if (*pcbAttrLen < needed) {
    *pcbAttrLen = needed;
    return SCARD_E_INSUFFICIENT_BUFFER;
  }
  memcpy(pbAttr, cachedATR_.data(), needed);
  *pcbAttrLen = needed;
  return SCARD_S_SUCCESS;
}

#endif /* __linux__ && !__ANDROID__ */
