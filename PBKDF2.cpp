#include "PBKDF2.h"
#include "util.h"
#include <chrono>

const static std::string PBKDF2_BENCHMARK_PASSWORD("password123");
const static std::string PBKDF2_BENCHMARK_SALT("0123456789ABCDEF");
 
std::string PBKDF2::PBKDF2(OpenSSL::Hash& hash,
    const std::string& password, const std::string& salt,
    std::size_t iterations, std::size_t length) {
  std::string res;

  for (std::size_t i = 1; res.size() < length; i++)
    res += F(hash, password, salt, iterations, i);

  return res.substr(0, length);
}

std::string PBKDF2::F(OpenSSL::Hash& hash,
    const std::string& password, const std::string& salt,
    std::size_t iterations, std::size_t i) {
  hash.reset();
  hash.update(password+salt+htobe32_str(i));
  std::string res, U = hash.digest();
  res = U;
  hash.reset();
  for (std::size_t i = 2; i < iterations; i++) {
    hash.update(password + U);
    U = hash.digest();
    hash.reset();
    for (std::size_t j = 0; j < U.size(); j++)
      res[j] ^= U[j];
  }
  return res;
}

std::size_t PBKDF2::benchmark(OpenSSL::Hash& hash, std::size_t time) {
  int i = 1;
  auto stop = std::chrono::milliseconds(time);
  auto start = std::chrono::steady_clock::now();
  hash.reset();
  hash.update(PBKDF2_BENCHMARK_PASSWORD + PBKDF2_BENCHMARK_SALT + htobe32_str(1));
  std::string res, U = hash.digest();
  res = U;
  hash.reset();
  while (true) {
    hash.update(PBKDF2_BENCHMARK_PASSWORD + U);
    U = hash.digest();
    hash.reset();
    for (std::size_t j = 0; j < U.size(); j++)
      res[j] ^= U[j];
    i++;
    if (i % 512 == 0)
      if (std::chrono::steady_clock::now() - start >= stop)
        break;
  }
  return i;
}
