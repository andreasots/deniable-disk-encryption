#include "header.h"
#include "crypto.h"
#include "PBKDF2.h"
#include <gcrypt.h>

void Params::store(std::ostream& device) {
  device.seekp(0);
  device.exceptions(std::ios::failbit | std::ios::badbit);
  
  // Wipe header block
  {
    char buf[block_size];
    std::memset(buf, 0, block_size);
    device.write(buf, block_size);
    device.seekp(0);
  }

  device.write(HEADER_MAGIC_STR, sizeof(HEADER_MAGIC_STR)-1);
  device.write(htole32_str(block_size).data(), 4);
  device.write(htole32_str(key_size).data(), 4);
  device.write(htole32_str(device_cipher.size()).data(), 4);
  device.write(device_cipher.data(), device_cipher.size());
  device.write(htole32_str(hash.size()).data(), 4);
  device.write(hash.data(), hash.size());
  device.write(htole32_str(salt.size()).data(), 4);
  device.write(salt.data(), salt.size());
  device.write(htole32_str(iters).data(), 4);
}

void Params::load(std::istream& device) {
  device.seekg(0);
  device.exceptions(std::ios::failbit | std::ios::badbit | std::ios::eofbit);
  
  { //  Magic number
    char buf[sizeof(HEADER_MAGIC_STR)];
    device.read(buf, sizeof(HEADER_MAGIC_STR)-1);
    buf[sizeof(HEADER_MAGIC_STR)-1] = '\0';
    if (std::string(buf) != HEADER_MAGIC_STR)
      throw std::runtime_error("Wrong magic number");
  }
  
  {  // block size
    char buf[4];
    device.read(buf, 4);
    block_size = le32toh_str(std::string(buf, 4));
    if (device.tellg() > block_size)
      throw std::out_of_range("block size");
  }

  {  // key size
    char buf[4];
    device.read(buf, 4);
    if (device.tellg() > block_size)
      throw std::out_of_range("key size");
    key_size = le32toh_str(std::string(buf, 4));
  }


  {  // dm-crypt cipher
    char buf[4];
    device.read(buf, 4);
    if (device.tellg() > block_size)
      throw std::out_of_range("cipher size");
    std::size_t cipher_size = le32toh_str(std::string(buf, 4));
    if (static_cast<std::uint64_t>(device.tellg()) + cipher_size > block_size)
      throw std::out_of_range("cipher");
    char *cipher_buf = new char[cipher_size];
    device.read(cipher_buf, cipher_size);
    device_cipher = std::string(cipher_buf, cipher_size);
    delete[] cipher_buf;
  }
  
  { // hash function
    char buf[4];
    device.read(buf, 4);
    if (device.tellg() > block_size)
      throw std::out_of_range("hash length");
    std::size_t hash_size = le32toh_str(std::string(buf, 4));
    if (static_cast<std::uint64_t>(device.tellg()) + hash_size > block_size)
      throw std::out_of_range("hash");
    char *hash_buf = new char[hash_size];
    device.read(hash_buf, hash_size);
    hash = std::string(hash_buf, hash_size);
    delete[] hash_buf;
  }

  { // salt
    char buf[4];
    device.read(buf, 4);
    if (device.tellg() > block_size)
      throw std::out_of_range("salt size");
    std::size_t salt_size = le32toh_str(std::string(buf, 4));
    if (static_cast<std::uint64_t>(device.tellg()) + salt_size > block_size)
      throw std::out_of_range("salt");
    char *salt_buf = new char[salt_size];
    device.read(salt_buf, salt_size);
    salt = std::string(salt_buf, salt_size);
    delete[] salt_buf;
  }

  { // PBKDF2 iterations
    char buf[4];
    device.read(buf, 4);
    if (device.tellg() > block_size)
      throw std::out_of_range("iterations");
    iters = le32toh_str(std::string(buf, 4));
  }
}

std::uint64_t Params::locate_superblock(const std::string& passphrase,
    std::uint64_t blocks) {
  Hash _hash(hash);
  gpg_error_t error;
  gcry_mpi_t x = nullptr, divisor, L;
  {
    std::string hash_max(_hash.size(), '\xFF');
    if ((error = gcry_mpi_scan(&divisor, GCRYMPI_FMT_USG,
            hash_max.data(), hash_max.size(), nullptr)) != GPG_ERR_NO_ERROR)
      throw std::system_error(error, gpg_category());
    blocks = htobe64(blocks-1);
    if ((error = gcry_mpi_scan(&L, GCRYMPI_FMT_USG,
            &blocks, 8, nullptr)) != GPG_ERR_NO_ERROR)
      throw std::system_error(error, gpg_category());
    gcry_mpi_div(divisor, nullptr, divisor, L, 0);
  }

  std::size_t i = 1;
  do {
    gcry_mpi_release(x);
    std::string key = PBKDF2::F(_hash, passphrase, salt, iters, i);
    if ((error = gcry_mpi_scan(&x, GCRYMPI_FMT_USG,
            key.data(), key.size(), nullptr)) != GPG_ERR_NO_ERROR)
      throw std::system_error(error, gpg_category());
    gcry_mpi_div(x, nullptr, x, divisor, 0);
  } while (gcry_mpi_cmp(x, L) >= 0);

  unsigned char buf[8];
  std::size_t written = 0;
  if ((error = gcry_mpi_print(GCRYMPI_FMT_USG, buf, 8, &written, x))
        != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());

  std::uint64_t ret = 0;
  std::size_t offset = 0;
  for (i = 0; i < written; i++) {
    ret = buf[i] << offset;
    offset += 8;
  }

  return ret+1;
}
