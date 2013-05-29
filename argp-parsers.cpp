#include "argp-parsers.h"
#include "blockdevice.h"
#include "header.h"
#include <sstream>

argp_option params_options[] = {
  {"block-size", 'b', "BYTES", 1, "Block size in bytes", 0},
  {"disk-cipher", 'c', "CIPHER", 0,
    "Cipher to use to encrypt the DEVICE (see /proc/crypto)", 0},
  {"header-cipher", 'C', "CIPHER", 0,
    "Cipher to use to encrypt partition headers", 0},
  {"hash", 'H', "HASH", 0,
    "Hash algorithm to use to generate partition keys from passphrases", 0},
  {"iter-time", 'i', "MS", 0, "PBKDF2 iteration time in milliseconds", 0},
  {"key-size", 's', "BITS", 0, "Disk encryption key size", 0},
  {nullptr, 0, nullptr, 0, nullptr, 0}
};

error_t parse_device(int key, char *arg, struct argp_state *state) {
  BlockDevice &device = *reinterpret_cast<BlockDevice*>(state->input);
  switch (key) {
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

template <class T> T from_string(const std::string& str) {
  T ret;
  std::stringstream(str) >> ret;
  return ret;
}

error_t parse_params(int key, char *arg, struct argp_state *state) {
  Params &params = *reinterpret_cast<Params*>(state->input);
  switch(key) {
    case 'b':
      params.block_size = std::max(from_string<int>(arg), 0);
      if (params.block_size == 0)
        argp_failure(state, 1, 0, "Block size must be a positive integer");
      if (params.block_size % 512)
        argp_failure(state, 1, 0, "Block size must be a multiple of 512 bytes");
      break;
    case 'c':
      params.device_cipher = arg;
      break;
    case 'C':
      params.superblock_cipher = arg;
      break;
    case 'H':
      params.hash = arg;
      break;
    case 'i':
      params.iters = std::max(from_string<int>(arg), 0);
      if (params.iters == 0)
        argp_failure(state, 1, 0, "Iteration time must be a positive integer");
      break;
    case 's':
      params.key_size = std::max(from_string<int>(arg), 0);
      if (params.key_size == 0 || params.key_size % 8 != 0) 
        argp_failure(state, 1, 0, "Key size must be a multiple of 8 bits");
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

argp parsers[] = {
  {nullptr, parse_device, "DEVICE", nullptr, nullptr, nullptr, nullptr},
  {params_options, parse_params, nullptr, nullptr, nullptr, nullptr, nullptr}
};

std::unique_ptr<argp_child[]> new_subparser(const std::vector<std::string>& p) {
  std::unique_ptr<argp_child[]> ret(new argp_child[p.size()+1]);
  argp_child* next_child = ret.get();
  for (auto parser : p) {
    if (parser == "device") {
      next_child->argp = parsers+0;
      next_child->flags = 0;
      next_child->header = nullptr;
      next_child->group = 0;
    } else if (parser == "params") {
      next_child->argp = parsers+1;
      next_child->flags = 0;
      next_child->header = nullptr;
      next_child->group = 0;
    } else {
      throw std::invalid_argument(parser);
    }
    next_child++;
  }

  // Sentinel
  next_child->argp = nullptr;
  next_child->flags = 0;
  next_child->header = nullptr;
  next_child->group = 0;

  return ret;
}
