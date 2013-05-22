#include "openssl-hash.h"
#include <stdexcept>
#include <cstring>

OpenSSL::OpenSSL() {
  OpenSSL_add_all_digests();
}

OpenSSL::~OpenSSL() {
  EVP_cleanup();
}

OpenSSL& OpenSSL::instance() {
  static OpenSSL _instance;
  return _instance;
}

// from OpenSSL: apps/dgst.c:84
static void list_md_fn(const EVP_MD* m, const char* from, const char* to,
    void* arg) {
  const char *mname;
  /* Skip aliases */
  if (!m)
    return;
  mname = OBJ_nid2ln(EVP_MD_type(m));
  /* Skip shortnames */
  if (std::strcmp(from, mname))
    return;
  /* Skip clones */
  if (EVP_MD_flags(m) & EVP_MD_FLAG_PKEY_DIGEST)
    return;
  if (std::strchr(mname, ' '))
    mname = EVP_MD_name(m);
  reinterpret_cast<std::vector<std::string>*>(arg)->emplace_back(mname);
}

std::vector<std::string> OpenSSL::hash_functions() const {
  std::vector<std::string> ret;
  EVP_MD_do_all_sorted(list_md_fn, &ret);
  return ret;
}

OpenSSL::Hash OpenSSL::new_hash(const std::string& hash) const {
  auto digest = EVP_get_digestbyname(hash.c_str());
  if (!digest)
    throw std::runtime_error("Unknown hash function");
  auto ctx = EVP_MD_CTX_create();
  if (!ctx)
    throw std::runtime_error("Context creation failed");
  if (!EVP_DigestInit_ex(ctx, digest, nullptr))
    throw std::runtime_error("Context initialisation failed");
  return Hash(ctx);
}

OpenSSL::Hash::Hash(EVP_MD_CTX* context)
    : _context(context) {
}

OpenSSL::Hash::Hash(Hash&& hash)
    : _context(hash._context) {
  hash._context = nullptr;
}

OpenSSL::Hash::Hash(const OpenSSL::Hash& hash)
    : _context(EVP_MD_CTX_create()) {
  if (!_context)
    throw std::runtime_error("Context creation failed");
  EVP_MD_CTX_copy_ex(_context, hash._context);
}

OpenSSL::Hash::~Hash() {
  if (_context)
    EVP_MD_CTX_destroy(_context);
}

OpenSSL::Hash& OpenSSL::Hash::operator=(const OpenSSL::Hash& hash) {
  if (!_context && (_context = EVP_MD_CTX_create()) == nullptr)
    throw std::runtime_error("Context allocation failed");
  EVP_MD_CTX_copy_ex(_context, hash._context);
  return *this;
}

OpenSSL::Hash& OpenSSL::Hash::operator=(OpenSSL::Hash&& hash) {
  std::swap(_context, hash._context);
  return *this;
}

void OpenSSL::Hash::reset() {
  auto digest = EVP_MD_CTX_md(_context);
  if (!EVP_MD_CTX_cleanup(_context))
    throw std::runtime_error("Cleanup failed");
  if (!EVP_DigestInit(_context, digest))
    throw std::runtime_error("Context initialisation failed");
}

std::string OpenSSL::Hash::algo() const {
  return OBJ_nid2ln(EVP_MD_type(EVP_MD_CTX_md(_context)));
}

void OpenSSL::Hash::update(const std::string& message) {
  if (!EVP_DigestUpdate(_context, message.data(), message.size()))
    throw std::runtime_error("EVP_DigestUpdate failed");
}

std::string OpenSSL::Hash::digest() {
  unsigned char md[EVP_MD_CTX_size(_context)];
  if (!EVP_DigestFinal_ex(_context, md, nullptr))
    throw std::runtime_error("EVP_DigestFinal failed");
  return std::string(reinterpret_cast<char*>(md), sizeof(md));
}
