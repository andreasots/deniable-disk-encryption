#include "header.h"
#include "crypto.h"
#include "PBKDF2.h"

void Params::store(BlockDevice& device) {
  device.seek(0);
  
  // Wipe header block
  device.write(std::string(block_size, '\0'));
  device.seek(0);

  device.write(std::string(HEADER_MAGIC_STR, sizeof(HEADER_MAGIC_STR)-1));
  device.write(htole32_str(block_size));
  device.write(htole32_str(key_size));
  device.write(htole32_str(device_cipher.size()));
  device.write(device_cipher);
  device.write(htole32_str(superblock_cipher.size()));
  device.write(superblock_cipher);
  device.write(htole32_str(hash.size()));
  device.write(hash.data());
  device.write(htole32_str(salt.size()));
  device.write(salt.data());
  device.write(htole32_str(iters));
}

static std::string read_bytes(BlockDevice& device, std::size_t n,
    std::int64_t& bytes, const std::string& message) {
  if (bytes < n)
    throw std::out_of_range(message);
  bytes -= n;
  return device.read(n);
}

static inline std::uint32_t read_uint_le32(BlockDevice& device,
    std::int64_t& bytes, const std::string& message) {
  return le32toh_str(read_bytes(device, 4, bytes, message));
}

void Params::load(BlockDevice& device) {
  device.seek(0);
  std::int64_t bytes = 0;
  
  // magic number
  if (device.read(sizeof(HEADER_MAGIC_STR)-1) != HEADER_MAGIC_STR)
    throw std::runtime_error("Wrong magic number");
  bytes -= sizeof(HEADER_MAGIC_STR)-1;
  
  // block size
  block_size = le32toh_str(device.read(4));
  bytes += block_size - 4;
  if (bytes < 0)
    throw std::out_of_range("block size");

  // key size
  key_size = read_uint_le32(device, bytes, "key size");

  {  // dm-crypt cipher    
    std::size_t cipher_size = read_uint_le32(device, bytes,
        "device cipher size");
    device_cipher = read_bytes(device, cipher_size, bytes, "device cipher");
  }

  {  // libgcrypt cipher
    std::size_t cipher_size = read_uint_le32(device, bytes,
        "superblock cipher size");
    superblock_cipher = read_bytes(device, cipher_size, bytes,
        "superblock cipher");
  }
  
  {  // hash function
    std::size_t hash_size = read_uint_le32(device, bytes,
        "hash function size");
    hash = read_bytes(device, hash_size, bytes, "hash function");
  }

  {  // salt
    std::size_t salt_size = read_uint_le32(device, bytes, "salt size");
    salt = read_bytes(device, salt_size, bytes, "salt");
  }

  // PBKDF2 iterations
  iters = read_uint_le32(device, bytes, "PBKDF2 iterations");
}

std::uint64_t Params::locate_superblock(const std::string& passphrase,
    std::uint64_t blocks) const {
  Hash _hash(hash);
  gpg_error_t error;
  gcry_mpi_t x = nullptr, divisor, L;
  {
    std::string hash_max(_hash.size(), '\xFF');
    if ((error = gcry_mpi_scan(&divisor, GCRYMPI_FMT_USG,
            hash_max.data(), hash_max.size(), nullptr)) != GPG_ERR_NO_ERROR)
      throw std::system_error(gcrypt_error_code(error), gpg_category());
    blocks = htobe64(blocks-1);
    if ((error = gcry_mpi_scan(&L, GCRYMPI_FMT_USG,
            &blocks, 8, nullptr)) != GPG_ERR_NO_ERROR)
      throw std::system_error(gcrypt_error_code(error), gpg_category());
    gcry_mpi_div(divisor, nullptr, divisor, L, 0);
  }

  std::size_t i = 1;
  do {
    gcry_mpi_release(x);
    std::string key = PBKDF2::F(_hash, passphrase, salt, iters, i);
    if ((error = gcry_mpi_scan(&x, GCRYMPI_FMT_USG,
            key.data(), key.size(), nullptr)) != GPG_ERR_NO_ERROR)
      throw std::system_error(gcrypt_error_code(error), gpg_category());
    gcry_mpi_div(x, nullptr, x, divisor, 0);
  } while (gcry_mpi_cmp(x, L) >= 0);

  unsigned char buf[8];
  std::size_t written = 0;
  if ((error = gcry_mpi_print(GCRYMPI_FMT_USG, buf, 8, &written, x))
        != GPG_ERR_NO_ERROR)
    throw std::system_error(gcrypt_error_code(error), gpg_category());

  std::uint64_t ret = 0;
  std::size_t offset = 0;
  for (i = 0; i < written; i++) {
    ret = buf[i] << offset;
    offset += 8;
  }

  return ret+1;
}

Superblock::Superblock(const Params& _params, const std::string& passphrase,
    std::uint64_t _blocks)
    : params(_params), cipher(_params.superblock_cipher) {
  blocks.push_back(params.locate_superblock(passphrase, _blocks));
  Hash hash(params.hash);
  std::string key_iv = PBKDF2::PBKDF2(hash, passphrase, params.salt,
      params.iters, cipher.key_size()+cipher.block_size());
  cipher.set_key(key_iv.substr(0, cipher.key_size()));
  cipher.set_iv(key_iv.substr(cipher.key_size()));
}

void Superblock::store(BlockDevice& dev) {
  Hash hash(params.hash);
  std::string superblock;
  // Superblock format (everything is 8-byte aligned):
  //   hash of data in partition header
  //   number of blocks as a 64-bit little endian integer
  //   list of blocks as an array of 64-bit little endian integers
  superblock.reserve(8 + 8*(blocks.size()-1));
  superblock += htole64_str(blocks.size()-1);
  for (auto block = blocks.begin()+1; block != blocks.end(); block++)
    superblock += htole64_str(*block);
  hash.update(superblock.substr(0, params.block_size - ((hash.size()+7)/8)*8));
  dev.seek(blocks.front()*params.block_size);
  dev.write(hash.digest());
  dev.write(std::string(((hash.size()+7)/8)*8 - hash.size(), 0));
  dev.write(htole64_str(blocks.size()-1));
  dev.write(superblock.substr(0, params.block_size-((hash.size()+7)/8)*8-8));
  std::size_t offset = params.block_size-((hash.size()+7)/8)*8-8;
  for (auto block = blocks.begin()+1; offset < superblock.size(); block++) {
    dev.seek((*block)*params.block_size);
    dev.write(superblock.substr(offset, params.block_size));
    offset += params.block_size;
  }
}

void Superblock::load(BlockDevice& dev) {
  Hash hash(params.hash);
  dev.seek(blocks.front()*params.block_size);
  std::string superblock = dev.read(params.block_size);
  hash.update(superblock.substr(((hash.size()+7)/8)*8,
        params.block_size-((hash.size()+7)/8)*8));
  if (hash.digest() != superblock.substr(0, hash.size()))
    throw std::runtime_error("Checksum error");
  blocks.resize(1);
  std::uint64_t block_count =
    le64toh_str(superblock.substr(((hash.size()+7)/8)*8, 8));
  blocks.reserve(block_count + 1);
  auto current_block = blocks.begin();
  std::size_t offset = ((hash.size()+7)/8+1)*8;
  for (std::size_t i = params.block_size/8 - (hash.size()+7)/8 - 1;
      i != 0 && block_count > 0; i--, block_count--) {
    blocks.push_back(le64toh_str(superblock.substr(offset, 8)));
    offset += 8;
  }
  while(block_count > 0) {
    current_block++;
    dev.seek((*current_block)*params.block_size);
    superblock += dev.read(params.block_size);
    for (std::size_t i = 0; i < params.block_size/8 && block_count != 0;
        i++, block_count--) {
      blocks.push_back(le64toh_str(superblock.substr(offset, 8)));
      offset += 8;
    }
  }
}

