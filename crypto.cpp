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
    }
  } libgcrypt;
}

Hash::Hash(int algo) {
  gpg_error_t error;
  if ((error = gcry_md_test_algo(algo)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
  if ((error = gcry_md_open(&_handle, algo, 0)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
}

Hash::Hash(const std::string& name)
    : Hash(gcry_md_map_name(name.c_str())) {
}

Hash::Hash(const Hash& hash) {
  gpg_error_t error;
  if ((error = gcry_md_copy(&_handle, hash._handle)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
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
    throw std::system_error(error, gpg_category());
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

std::vector<std::string> hash_functions() {
  int num;
  gpg_error_t error;
  if ((error = gcry_md_list(nullptr, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
  int algos[num];
  if ((error = gcry_md_list(algos, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
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
    throw std::system_error(error, gpg_category());
  int algos[num];
  if ((error = gcry_cipher_list(algos, &num)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
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

