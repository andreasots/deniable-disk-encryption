#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <gcrypt.h>
#include <string>
#include <vector>

class Hash {
 public:
  explicit Hash(int algo = 0);
  explicit Hash(const std::string& name);
  Hash(const Hash&);
  Hash(Hash&&);
  ~Hash();
  Hash& operator=(const Hash&);
  Hash& operator=(Hash&&);

  int algo();
  std::string name();
  std::size_t size();

  void reset();
  void update(const std::string&);
  std::string digest();

 private:
  gcry_md_hd_t _handle;
};

class Symmetric {
};

static inline std::string random_string(std::size_t n) {
  unsigned char buf[n];
  gcry_randomize(buf, n, GCRY_STRONG_RANDOM);
  return std::string(reinterpret_cast<char*>(buf), n);
}

std::vector<std::string> hash_functions();
 
#endif  // CRYPTO_H_
