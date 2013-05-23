#ifndef HEADER_H_
#define HEADER_H_

#define HEADER_MAGIC_STR "\x7c\x32\xc7\x8d"

#include "util.h"
#include <fstream>
#include <stdexcept>
#include <string>
#include <cstring>

struct Params {
  std::size_t block_size, iters, key_size;
  std::string hash, cipher, salt;

  void store(const std::string& devname) {
    std::ofstream device(devname);
    device.exceptions(std::ios::failbit | std::ios::badbit);
    char buf[512];
    std::memset(buf, 0, 512);
    device.write(buf, 512);
    device.seekp(0);
    device.write(HEADER_MAGIC_STR, sizeof(HEADER_MAGIC_STR)-1);
    device.write(htole32_str(block_size).data(), 4);
    device.write(htole32_str(cipher.size()).data(), 4);
    device.write(cipher.data(), cipher.size());
    device.write(htole32_str(hash.size()).data(), 4);
    device.write(hash.data(), hash.size());
    device.write(htole32_str(salt.size()).data(), 4);
    device.write(salt.data(), salt.size());
    device.write(htole32_str(iters).data(), 4);
  }

  void load(const std::string& devname) {
    char buf[512];
    std::size_t offset = 0;
    std::ifstream device(devname);
    device.exceptions(std::ios::failbit | std::ios::badbit | std::ios::eofbit);
    device.read(buf, 512);

    if (std::string(buf, sizeof(HEADER_MAGIC_STR)-1) != HEADER_MAGIC_STR)
      throw std::runtime_error("Wrong magic number");
    offset += sizeof(HEADER_MAGIC_STR)-1;

    block_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;

    std::size_t cipher_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
    cipher = std::string(buf+offset, cipher_size);
    offset += cipher_size;

    std::size_t hash_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
    hash = std::string(buf+offset, hash_size);
    offset += hash_size;

    std::size_t salt_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
    salt = std::string(buf+offset, salt_size);
    offset += salt_size;

    iters = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
  }
};

#endif  // HEADER_H_
