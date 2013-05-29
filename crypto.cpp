#include "crypto.h"
#include "util.h"
#include <cstdlib>
#include <iostream>

namespace {
  static struct libgcrypt {
    libgcrypt() {
      if (!gcry_check_version(GCRYPT_VERSION)) {
        std::cerr << "libgcrypt version mismatch" << std::endl;
        std::exit(2);
      }
      gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
      gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
  } libgcrypt;
}

Hash::Hash(int algo) {
  gpg_error_t error;
  if ((error = gcry_md_open(&_handle, algo, 0)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
}

Hash::Hash(const std::string& name)
    : Hash(gcry_md_map_name(name.c_str())) {
}

Hash::Hash(const Hash& hash) {
  gpg_error_t error;
  if ((error = gcry_md_copy(&_handle, hash._handle)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
}

Hash::Hash(Hash&& hash)
    : _handle(hash._handle) {
  hash._handle = nullptr;
}

Hash::~Hash() {
  gcry_md_close(_handle);
}

Hash& Hash::operator=(const Hash& hash) {
  gcry_md_hd_t h;
  gpg_error_t error;
  if ((error = gcry_md_copy(&h, hash._handle)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  gcry_md_close(_handle);
  _handle = h;
  return *this;
}

Hash& Hash::operator=(Hash&& hash) {
  std::swap(_handle, hash._handle);
  return *this;
}

int Hash::algo() {
  return gcry_md_get_algo(_handle);
}

std::string Hash::name() {
  return gcry_md_algo_name(algo());
}

std::size_t Hash::size() {
  return gcry_md_get_algo_dlen(algo());
}

void Hash::reset() {
  gcry_md_reset(_handle);
}

void Hash::update(const std::string& data) {
  gcry_md_write(_handle, data.data(), data.size());
}

std::string Hash::digest() {
  gcry_md_final(_handle);
  return std::string(reinterpret_cast<char*>(gcry_md_read(_handle, 0)), size());
}

Symmetric::Symmetric(int algo)
    : _algo(algo) {
  gpg_error_t error;
  if ((error = gcry_cipher_open(&_handle, algo, GCRY_CIPHER_MODE_CBC, 0))
      != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
}

Symmetric::Symmetric(const std::string& name)
    : Symmetric(gcry_cipher_map_name(name.c_str())) {
}

Symmetric::Symmetric(Symmetric&& cipher)
    : _handle(cipher._handle) {
  cipher._handle = nullptr;
}

Symmetric::~Symmetric() {
  gcry_cipher_close(_handle);
}

Symmetric& Symmetric::operator=(Symmetric&& cipher) {
  std::swap(_handle, cipher._handle);
  return *this;
}

std::size_t Symmetric::key_size() {
  return gcry_cipher_get_algo_keylen(_algo);
}

std::size_t Symmetric::block_size() {
  return gcry_cipher_get_algo_blklen(_algo);
}

void Symmetric::set_key(const std::string& key) {
  gpg_error_t error;
  if ((error = gcry_cipher_setkey(_handle, key.data(), key.size()))
      != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
}

void Symmetric::set_iv(const std::string& iv) {
  gpg_error_t error;
  if ((error = gcry_cipher_setiv(_handle, iv.data(), iv.size()))
      != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
}

void Symmetric::reset() {
  gpg_error_t error;
  if ((error = gcry_cipher_reset(_handle)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
}

std::string Symmetric::encrypt(const std::string& data) {
  gpg_error_t error;
  char *buf = new char[data.size()];
  if ((error = gcry_cipher_encrypt(_handle, buf, data.size(), data.data(),
          data.size())) != GPG_ERR_NO_ERROR) {
    delete[] buf;
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  }
  std::string ret(buf, data.size());
  delete[] buf;
  return ret;
}

std::string Symmetric::decrypt(const std::string& data) {
  gpg_error_t error;
  char *buf = new char[data.size()];
  if ((error = gcry_cipher_decrypt(_handle, buf, data.size(), data.data(),
          data.size())) != GPG_ERR_NO_ERROR) {
    delete[] buf;
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  }
  std::string ret(buf, data.size());
  delete[] buf;
  return ret;
}

std::vector<std::string> hash_functions() {
  int num;
  gpg_error_t error;
  if ((error = gcry_md_list(nullptr, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  int algos[num];
  if ((error = gcry_md_list(algos, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  std::vector<std::string> ret;
  ret.reserve(num);
  for (int algo : algos)
    if (gcry_md_test_algo(algo) == GPG_ERR_NO_ERROR)
      ret.push_back(gcry_md_algo_name(algo));
  return ret;
}

std::vector<std::string> block_ciphers() {
  int num;
  gpg_error_t error;
  if ((error = gcry_cipher_list(nullptr, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  int algos[num];
  if ((error = gcry_cipher_list(algos, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());
  std::vector<std::string> ret;
  ret.reserve(num);
  for (int algo : algos) {
    if (gcry_cipher_algo_info(algo, GCRYCTL_TEST_ALGO,
          nullptr, nullptr) != GPG_ERR_NO_ERROR)
      continue;
    gcry_cipher_hd_t handle;
    if ((error = gcry_cipher_open(&handle, algo,
            GCRY_CIPHER_MODE_CBC, 0)) != GPG_ERR_NO_ERROR)
      continue;
    gcry_cipher_close(handle);
    ret.push_back(gcry_cipher_algo_name(algo));
  }
  return ret;
}

