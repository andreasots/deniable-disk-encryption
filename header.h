#ifndef HEADER_H_
#define HEADER_H_

#define HEADER_MAGIC_STR "\x7c\x32\xc7\x8d"

#include "util.h"
#include <fstream>
#include <stdexcept>

struct Params {
  std::size_t block_size, iters, key_size;
  std::string cipher;
  OpenSSL::Hash hash;

  void store(const std::string& devname) {
    std::ofstream device(devname);
    device.exceptions(std::ios::failbit | std::ios::badbit);
    device.write(HEADER_MAGIC_STR, sizeof(HEADER_MAGIC_STR));
    device.write(htole32_str(block_size).data(), 4);
    device.write(htole32_str(cipher.size()).data(), 4);
    device.write(cipher.data(), cipher.size());
    auto algo = hash.algo();
    device.write(htole32_str(algo.size()).data(), 4);
    device.write(algo.data(), algo.size());
    device.write(htole32_str(iters).data(), 4);
  }

  void load(const std::string& devname) {
    char buf[512];
    std::size_t offset = 0;
    std::ifstream device(devname);
    device.exceptions(std::ios::failbit | std::ios::badbit | std::ios::eofbit);
    device.read(buf, 512);

    if (std::string(buf, sizeof(HEADER_MAGIC_STR)) != HEADER_MAGIC_STR)
      throw std::runtime_error("Wrong magic number");
    offset += sizeof(HEADER_MAGIC_STR);

    block_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;

    std::size_t cipher_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
    cipher = std::string(buf+offset, cipher_size);
    offset += cipher_size;

    std::size_t hash_size = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
    hash = OpenSSL::instance().new_hash(std::string(buf+offset, hash_size));
    offset += hash_size;

    iters = le32toh_str(std::string(buf+offset, 4));
    offset += 4;
  }
};

#endif  // HEADER_H_
