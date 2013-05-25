#include "blockdevice.h"
#include "header.h"
#include <argp.h>
#include <iostream>
#include <cstdlib>
#include <iomanip>

const char* doc = "View parameter area on DEVICE";

error_t parse_opt(int key, char *arg, struct argp_state *state) {
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

int main(int argc, char *argv[]) {
  BlockDevice device;

  argp argp = {nullptr, parse_opt, "DEVICE", doc, nullptr, nullptr, nullptr};
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
  
  return 0;
}
