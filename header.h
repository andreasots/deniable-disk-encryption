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

  void store(const std::string& devname);
  void load(const std::string& devname);
  std::uint64_t locate_superblock(const std::string& passphrase, std::uint64_t blocks);
};

#endif  // HEADER_H_
