#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <gcrypt.h>
#include <string>
#include <vector>

#include <cassert>

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

static inline std::string nonce(std::size_t n) {
  unsigned char buf[n];
  gcry_create_nonce(buf, n);
  return std::string(reinterpret_cast<char*>(buf), n);
}

std::vector<std::string> hash_functions();
std::vector<std::string> block_ciphers();
 
#endif  // CRYPTO_H_
