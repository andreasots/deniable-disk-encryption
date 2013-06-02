#include "blockdevice.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <system_error>
#include <sys/ioctl.h>
#include <linux/fs.h>

BlockDevice::BlockDevice()
  : _fd(-1) {
}

BlockDevice::BlockDevice(const std::string& name)
  : _fd(::open(name.c_str(), O_RDWR)) {
  if (_fd == -1)
    throw std::system_error(errno, std::system_category());
}

BlockDevice::BlockDevice(BlockDevice&& dev)
  : _fd(dev._fd) {
}

BlockDevice::~BlockDevice() {
  if (this->open())
    close(_fd);
}

BlockDevice& BlockDevice::operator=(BlockDevice&& dev) {
  std::swap(_fd, dev._fd);
  return *this;
}

bool BlockDevice::open() const {
  return _fd != -1;
}

unsigned BlockDevice::major() const {
  struct stat info;
  if (fstat(_fd, &info) == -1)
    throw std::system_error(errno, std::system_category());
  return ::major(info.st_rdev);
}

unsigned BlockDevice::minor() const {
  struct stat info;
  if (fstat(_fd, &info) == -1)
    throw std::system_error(errno, std::system_category());
  return ::minor(info.st_rdev);
}

std::string BlockDevice::read(std::size_t n) {
  char *buf = new char[n];
  std::size_t total = 0;
  ssize_t current;
  while (total < n) {
    if ((current = ::read(_fd, buf+total, n-total)) == -1) {
      delete[] buf;
      throw std::system_error(errno, std::system_category());
    } else if (current == 0) {
      throw std::out_of_range("EOF reached");
    }
    total += current;
  }
  std::string ret(buf, n);
  delete[] buf;
  return ret;
}

void BlockDevice::write(const std::string& data) {
  std::size_t total = 0;
  ssize_t current;
  while (total < data.size()) {
    if ((current = ::write(_fd, data.data()+total, data.size()-total)) == -1)
      throw std::system_error(errno, std::system_category());
    total += current;
  }
}

std::uint64_t BlockDevice::size() const {
  std::uint64_t res;
  if (ioctl(_fd, BLKGETSIZE64, &res) == -1)
    throw std::system_error(errno, std::system_category());
  return res;
}

off_t BlockDevice::seek(off_t offset, int whence) {
  off_t ret = lseek(_fd, offset, whence);
  if (ret == -1)
    throw std::system_error(errno, std::system_category());
  return ret;
}
