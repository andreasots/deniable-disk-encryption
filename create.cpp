#include "blockdevice.h"
#include "header.h"
#include "pinentry.h"
#include <argp.h>
#include <iostream>
#include <cstdlib>

const char* doc = "Create a new encrypted partition on DEVICE";

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
  
  if (blocks <= 1) {
    std::cerr << "No room for any partitions." << std::endl;
    return 1;
  }

  std::string passphrase;
  Pinentry pinentry;
  pinentry.SETDESC("Enter passphrases for all partitions on this volume. "
      "Enter an empty passphrase after last passphrase.");
  pinentry.SETPROMPT("Passphrase:");
  do {
    passphrase = pinentry.GETPIN();
    std::cout << params.locate_superblock(passphrase, blocks) << std::endl;
  } while (passphrase != "");

  return 0;
}
