#ifndef OPENSSL_HASH_H_
#define OPENSSL_HASH_H_

#include <string>
#include <vector>

#include <openssl/evp.h>

class OpenSSL {
 public:
  class Hash {
   public:
    explicit Hash(EVP_MD_CTX* ctx = nullptr);
    Hash(Hash&&);
    Hash(const Hash&);
    ~Hash();
    Hash& operator=(const Hash&);
    Hash& operator=(Hash&&);
    void reset();
    std::string algo() const;

    void update(const std::string&);
    std::string digest();

   private:
    EVP_MD_CTX* _context;
  };

  OpenSSL(const OpenSSL&) = delete;
  ~OpenSSL();
  OpenSSL& operator=(const OpenSSL&) = delete;
  static OpenSSL& instance();
  std::vector<std::string> hash_functions() const;
  Hash new_hash(const std::string&) const;

 private:
  OpenSSL();
};

#endif  // OPENSSL_HASH_H_
