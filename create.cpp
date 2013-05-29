#include "blockdevice.h"
#include "header.h"
#include "pinentry.h"
#include "argp-parsers.h"
#include <argp.h>
#include <iostream>
#include <cstdlib>

const char* doc = "Create a new encrypted partition on DEVICE";

error_t init_parsers(int key, char*, argp_state* state) {
  if (key == ARGP_KEY_INIT) {
    state->child_inputs[0] = state->input;
    return 0;
  }
  return ARGP_ERR_UNKNOWN;
}

int main(int argc, char *argv[])
  try {
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

    if (blocks <= 1) {
      std::cerr << "Error: No room for any partitions." << std::endl;
      return 1;
    }

    std::vector<bool> allocated_blocks(blocks);
    allocated_blocks[0] = true;

    std::string passphrase;
    Pinentry pinentry;
    pinentry.SETDESC("Enter passphrases for all partitions on this volume. "
        "Enter an empty passphrase after last passphrase.");
    pinentry.SETPROMPT("Passphrase:");
    while ((passphrase = pinentry.GETPIN()) != "") {
      Superblock superblock(params, passphrase, blocks);
      std::cout << superblock.blocks.front() << std::endl;
      try {
        superblock.load(device);
        for (auto block : superblock.blocks)
          allocated_blocks[block] = true;
      } catch(...) {
        pinentry.SETERROR("No partition found for that passphrase.");
      }
    } while (passphrase != "");
    
    return 0;
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
