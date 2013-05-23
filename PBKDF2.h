#ifndef PBKDF2_H_
#define PBKDF2_H_

#include "crypto.h"
#include <string>
#include <cstddef>

namespace PBKDF2 {
  std::size_t benchmark(Hash& hash, std::size_t time);
  std::string F(Hash& hash, const std::string& password, 
      const std::string& salt, std::size_t iterations, std::size_t i);
  std::string PBKDF2(Hash& hash, const std::string& password, 
      const std::string& salt, std::size_t iterations, std::size_t length);
}

#endif  // PBKDF2_H_
