#ifndef BLOCKDEVICE_H_
#define BLOCKDEVICE_H_

#include <cstdint>
#include <string>

#include <sys/types.h>

class BlockDevice {
 public:
  BlockDevice();
  explicit BlockDevice(const std::string&);
  BlockDevice(const BlockDevice&) = delete;
  BlockDevice(BlockDevice&&);
  ~BlockDevice();
  BlockDevice& operator=(const BlockDevice&) = delete;
  BlockDevice& operator=(BlockDevice&&);

  bool open() const;
  unsigned major() const;
  unsigned minor() const;

  std::string read(std::size_t n);
  void write(const std::string&);
  off_t seek(off_t offset, int whence = SEEK_SET);

  std::uint64_t size() const;

 private:
  int _fd;
};

#endif  // BLOCKDEVICE_H_
