#include "getpass.h"
#include <termios.h>
#include <unistd.h>
#include <cerrno>
#include <system_error>
#include <sys/stat.h>
#include <fcntl.h>

std::string getpass() {
  int fd = open("/dev/tty", O_RDONLY);
  if (fd == -1)
    throw std::system_error(errno, std::system_category());

  termios termios;
  if (tcgetattr(fd, &termios) == -1)
    throw std::system_error(errno, std::system_category());

  int old_lflag = termios.c_lflag;
  termios.c_lflag &= ~ECHO;

  if (tcsetattr(fd, TCSAFLUSH, &termios) == -1)
    throw std::system_error(errno, std::system_category());

  std::string ret;
  char c = 0;
  do {
    if (read(fd, &c, 1) == -1)
      throw std::system_error(errno, std::system_category());
    ret.push_back(c);
  } while (c != '\n');
  ret.pop_back();
  
  termios.c_lflag = old_lflag;
  if (tcsetattr(fd, TCSAFLUSH, &termios) == -1)
    throw std::system_error(errno, std::system_category());

  if (close(fd) == -1)
    throw std::system_error(errno, std::system_category());

  return ret;
}
