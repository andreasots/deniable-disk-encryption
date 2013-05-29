#include "blockdevice.h"
#include "header.h"
#include "argp-parsers.h"
#include <argp.h>
#include <iostream>
#include <cstdlib>
#include <iomanip>

const char* doc = "View parameter area on DEVICE";

error_t init_parsers(int key, char*, argp_state* state) {
  if (key == ARGP_KEY_INIT) {
    state->child_inputs[0] = state->input;
    return 0;
  }
  return ARGP_ERR_UNKNOWN;
}

int main(int argc, char *argv[]) {
  BlockDevice device;

  auto parsers = new_subparser({"device"});
  argp argp = {nullptr, init_parsers, nullptr, doc, parsers.get(), nullptr,
    nullptr};
  argp_parse(&argp, argc, argv, 0, nullptr, &device);
  
  Params params;
  try {
    params.load(device);
  } catch(const std::exception& e) {
    std::cerr << "Error: Header corrupt." << std::endl;
    return 1;
  }
  std::uint64_t blocks = device.size()/params.block_size;

  std::cout << "Block size: " << params.block_size << " bytes" << std::endl;
  std::cout << "Blocks total: " << blocks << std::endl;
  std::cout << "PBKDF2 iterations: " << params.iters << std::endl;
  std::cout << "PBKDF2 salt: ";
  std::cout << std::hex;
  for (char c : params.salt) {
    std::cout << std::setw(2) << std::setfill('0');
    std::cout << static_cast<int>(static_cast<unsigned char>(c));
  }
  std::cout << std::dec << std::endl;
  std::cout << "Key size: " << params.key_size*8 << " bits" << std::endl;
  std::cout << "Hash algorithm: " << params.hash << std::endl;
  std::cout << "Encryption algorithm: " << params.device_cipher << std::endl;
  std::cout << "Superblock encryption algorithm: " << params.superblock_cipher
    << std::endl;
  
  return 0;
}
