#include "PBKDF2.h"
#include "crypto.h"
#include "header.h"
#include "util.h"

#include <openssl/rand.h>

#include <argp.h>
#include <iostream>
#include "blockdevice.h"
#include <sstream>
#include <stdexcept>
#include <chrono>

std::size_t block_size = 4 << 20; // 4 MiB
const char* cipher = "aes-cbc-essiv:sha256";
const char* superblock_cipher = "AES256";
const char* hash_algo = "SHA256";
std::size_t iter_time = 1000;
std::size_t key_size = 256;

argp_option options[] = {
  {"block-size", 'b', "BYTES", 0, "Block size in bytes", 0},
  {"disk-cipher", 'c', "CIPHER", 0, "Cipher to use to encrypt the DEVICE", 0},
  {"header-cipher", 'C', "CIPHER", 0,
    "Cipher to use to encrypt partition headers", 0},
  {"hash", 'H', "HASH", 0,
    "Hash algorithm to use to generate partition keys from passphrases", 0},
  {"iter-time", 'i', "MS", 0, "PBKDF2 iteration time in milliseconds", 0},
  {"key-size", 's', "BITS", 0, "Disk encryption key size", 0},
  {nullptr, 0, nullptr, 0, nullptr, 0}
};

const char* doc = "Create an encrypted volume on DEVICE\v\
Default block size: 4194304 bytes or 4 MiB\n\
Default disk cipher: aes-cbc-essiv:sha256\n\
Default disk encryption key length: 256 bits\n\
Default header cipher: AES256\n\
Default hash algorithm: SHA256\n\
Default PBKDF2 iteration time: 1000 ms or one second";


template <class T> T from_string(const std::string& str) {
  T ret;
  std::stringstream(str) >> ret;
  return ret;
}

BlockDevice device;

error_t parse_opt(int key, char *arg, struct argp_state *state) {
  Params *params = reinterpret_cast<Params*>(state->input);
  switch(key) {
    case 'b':
      params->block_size = std::max(from_string<int>(arg), 0);
      if (params->block_size < 512)
        argp_failure(state, 1, 0, "Block size must be at least 512 bytes");
      break;
    case 'c':
      params->device_cipher = arg;
      break;
    case 'C':
      params->superblock_cipher = arg;
      break;
    case 'H':
      params->hash = arg;
      break;
    case 'i':
      params->iters = std::max(from_string<int>(arg), 0);
      if (params->iters == 0)
        argp_failure(state, 1, 0, "Iteration time must be a positive integer");
      break;
    case 's':
      params->key_size = std::max(from_string<int>(arg), 0);
      if (params->key_size == 0 || params->key_size % 8 != 0) 
        argp_failure(state, 1, 0, "Key size must be a multiple of 8 bits");
      break;
    case ARGP_KEY_ARG:
      if (device.open())
        argp_failure(state, 1, 0, "Too many arguments");
      try {
        device = BlockDevice(arg);
      } catch(const std::exception& e) {
        argp_failure(state, 1, 0, e.what());
      }
      break;
    case ARGP_KEY_END:
      if (!device.open())
        argp_failure(state, 1, 0, "Too few arguments");
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  Params params;
  params.block_size = 4 << 20;
  params.iters = 1000;
  params.key_size = 256/8;
  params.hash = "SHA256";
  params.device_cipher = "aes-cbc-essiv:sha256";
  params.superblock_cipher = "AES256";
  params.salt = nonce(16);

  argp argp = {options, parse_opt, "DEVICE", doc, nullptr, nullptr, nullptr};
  argp_parse(&argp, argc, argv, 0, nullptr, &params);

  Hash hash(hash_algo);

  params.iters = PBKDF2::benchmark(hash, params.iters);
  params.iters /= (key_size + hash.size()-1)/hash.size();

  try {
    params.store(device);
  } catch(const std::exception& e) {
    std::cerr << "Device " << argv[optind] << " doesn't exist or access ";
    std::cerr << "denied." << std::endl;
    return 1;
  }
  
  return 0;
}
