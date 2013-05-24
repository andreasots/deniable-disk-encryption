#ifndef HEADER_H_
#define HEADER_H_

#define HEADER_MAGIC_STR "\x7c\x32\xc7\x8d"

#include "util.h"
#include <fstream>
#include <stdexcept>
#include <string>
#include <cstring>
#include <vector>

struct Params {
  std::size_t block_size, iters, key_size;
  std::string hash, cipher, salt;

  void store(std::ostream& devname);
  void load(std::istream& devname);
  std::uint64_t locate_superblock(const std::string& passphrase,
      std::uint64_t blocks);
};

struct Superblock {
  std::vector<std::uint64_t> blocks;
  const Params& param;
  const std::string key, iv;

  Superblock(const Params&, const std::string& passphrase);

  void store(std::ostream& dev);
  void load(std::istream& dev);
};

#endif  // HEADER_H_
