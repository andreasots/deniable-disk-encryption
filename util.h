#ifndef UTIL_H_
#define UTIL_H_

#include <cstdint>
#include <string>
#include <system_error>
#include <gpg-error.h>

class gpg_category : public std::error_category {
 public:
  virtual const char* name() const noexcept {
    return "GPG";
  }

  virtual std::string message(int code) const noexcept {
    return gpg_strsource(code) + std::string(": ") + gpg_strerror(code);
  }
};

// gcrypt has a bug that sets the error source to GPG_ERR_SOURCE_USER_1
static inline gpg_error_t gcrypt_error_code(gpg_error_t code) {
  return gpg_err_make(GPG_ERR_SOURCE_GCRYPT, gpg_err_code(code));
}

static inline std::string htole32_str(std::uint32_t i) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return std::string(reinterpret_cast<char*>(&i), 4);
#else
  std::string ret(4, '\x00');
  ret[0] = (i >> 24) & 0xFF;
  ret[1] = (i >> 16) & 0xFF;
  ret[2] = (i >> 8) & 0xFF;
  ret[3] = i & 0xFF;
  return ret;
#endif
}

static inline std::uint32_t le32toh_str(const std::string& str) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return *reinterpret_cast<const std::uint32_t*>(str.data());
#else
  return (((((str[0] << 8) | str[1]) << 8) | str[2]) << 8) | str[3];
#endif
}

static inline std::string htobe32_str(std::uint32_t i) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return std::string(reinterpret_cast<char*>(&i), 4);
#else
  std::string ret(4, '\x00');
  ret[0] = i & 0xFF;
  ret[1] = (i >> 8) & 0xFF;
  ret[2] = (i >> 16) & 0xFF;
  ret[3] = (i >> 24) & 0xFF;
  return ret;
#endif
}

static inline std::uint32_t be32toh_str(const std::string& str) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return *reinterpret_cast<const std::uint32_t*>(str.data());
#else
    return (((((str[3] << 8) | str[2]) << 8) | str[1]) << 8) | str[0];
#endif
}

#endif
