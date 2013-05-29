#include "blockdevice.h"
#include "header.h"
#include "pinentry.h"
#include "argp-parsers.h"
#include <argp.h>
#include <iostream>
#include <cstdlib>

const char* doc = "Create a new encrypted partition on DEVICE";

argp_option options[] = {
  {"blocks", 'b', "BLOCKS", 0, "Number of blocks to allocate for the "
    "partition", 0},
  {"partition-size", 's', "BLOCKS", 0, "Size of the partition in blocks. "
    "This can be greater than the number of blocks allocated for the "
    "partition.", 0},
  {nullptr, 0, nullptr, 0, nullptr, 0}
};

struct State {
  std::uint64_t blocks = 0;
  std::uint64_t partition_size = 0;
  BlockDevice device;
};

error_t init_parsers(int key, char* arg, argp_state* state) {
  State& args = *reinterpret_cast<State*>(state->input);
  switch (key) {
    case 'b':
      args.blocks = std::max<std::int64_t>(from_string<std::int64_t>(arg), 0);
      if (args.blocks == 0)
        argp_failure(state, 1, 0, "Number of blocks must be positive");
      break;
    case 's':
      std::uint64_t size = from_string<std::int64_t>(arg);
      args.partition_size = size;
      if (size == 0)
        argp_failure(state, 1, 0, "Partition size must be positive");
      break;
    case ARGP_KEY_INIT:
      state->child_inputs[0] = &args.device;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int main(int argc, char *argv[])
  try {
    State state;
    auto parsers = new_subparser({"device"});
    argp argp = {options, init_parsers, nullptr, doc, parsers.get(), nullptr,
      nullptr};
    argp_parse(&argp, argc, argv, 0, nullptr, &state);

    Params params;

    try {
      params.load(state.device);
    } catch(const std::exception& e) {
      std::cerr << "Error: Header corrupt." << std::endl;
      return 1;
    }
    std::uint64_t blocks = state.device.size()/params.block_size;

    if (blocks <= 1) {
      std::cerr << "Error: No room for any partitions." << std::endl;
      return 1;
    }

    if (state.partition_size == 0)
      state.partition_size =
        state.blocks-Superblock::size_in_blocks(params, state.blocks);

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
        superblock.load(state.device);
        for (auto block : superblock.blocks)
          allocated_blocks[block] = true;
      } catch(...) {
        pinentry.SETERROR("No partition found for that passphrase.");
      }
    } while (passphrase != "");

    std::size_t free_blocks = 0;
    for (bool allocated : allocated_blocks)
      free_blocks++;

    std::cout << free_blocks << " blocks free." << std::endl;
    
    return 0;
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
