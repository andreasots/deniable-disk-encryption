#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <gcrypt.h>
#include <string>
#include <vector>

#include <cassert>

class Hash {
 public:
  explicit Hash(int algo);
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
 public:
  explicit Symmetric(int algo);
  explicit Symmetric(const std::string& name);
  Symmetric(const Symmetric&) = delete;
  Symmetric(Symmetric&&);
  ~Symmetric();
  Symmetric& operator=(const Symmetric&) = delete;
  Symmetric& operator=(Symmetric&&);

  std::size_t key_size();
  std::size_t block_size();

  void set_key(const std::string&);
  void set_iv(const std::string&);

  void reset();
  std::string encrypt(const std::string&);
  std::string decrypt(const std::string&);

 private:
  gcry_cipher_hd_t _handle;
  int _algo;
};

static inline std::string nonce(std::size_t n) {
  unsigned char buf[n];
  gcry_create_nonce(buf, n);
  return std::string(reinterpret_cast<char*>(buf), n);
}

std::vector<std::string> hash_functions();
std::vector<std::string> block_ciphers();
 
#endif  // CRYPTO_H_
