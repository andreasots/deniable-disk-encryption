#ifndef HEADER_H_
#define HEADER_H_

#define HEADER_MAGIC_STR "\x7c\x32\xc7\x8d"

#include "util.h"
#include "crypto.h"
#include "blockdevice.h"
#include <fstream>
#include <stdexcept>
#include <string>
#include <cstring>
#include <vector>

struct Params {
  std::size_t block_size, iters, key_size;
  std::string hash, device_cipher, superblock_cipher, salt;

  void store(BlockDevice& dev);
  void load(BlockDevice& dev);
  std::uint64_t locate_superblock(const std::string& passphrase,
      std::uint64_t blocks) const;
};

struct Superblock {
  std::vector<std::uint64_t> blocks;
  std::size_t offset = 1;
  const Params& params;
  Symmetric cipher;

  Superblock(const Params&, const std::string&, std::uint64_t);

  void store(BlockDevice& dev);
  void load(BlockDevice& dev);

  static std::uint64_t size_in_blocks(const Params& params,
      std::uint64_t blocks);
};

#endif  // HEADER_H_
