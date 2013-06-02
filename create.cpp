#include "blockdevice.h"
#include "header.h"
#include "pinentry.h"
#include "argp-parsers.h"
#include <argp.h>
#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <random>

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
    case 's': {
        auto size = from_string<std::int64_t>(arg);
        args.partition_size = size;
        if (size <= 0)
          argp_failure(state, 1, 0, "Partition size must be positive");
        break;
      }
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

    std::vector<bool> allocated_blocks(blocks);
    allocated_blocks[0] = true;

    std::string passphrase;
    Pinentry pinentry;
    pinentry.SETDESC("Enter passphrases for all partitions on this volume. "
        "Enter an empty passphrase after last passphrase.");
    pinentry.SETPROMPT("Passphrase:");
    while ((passphrase = pinentry.GETPIN()) != "") {
      Superblock superblock(params, passphrase, blocks);
      try {
        superblock.load(state.device);
        for (auto block : superblock.blocks)
          allocated_blocks[block] = true;
      } catch(...) {
        pinentry.SETERROR("No partition found for that passphrase.");
      }
    }

    std::size_t free_blocks = 0;
    for (bool allocated : allocated_blocks)
      if (!allocated)
        free_blocks++;

    std::cout << free_blocks << " blocks free." << std::endl;

    if (free_blocks == 0) {
      std::cout << "Error: not enough free space." << std::endl;
      return 1;
    }

    if (state.blocks == 0)
      state.blocks = free_blocks;
    if (state.partition_size == 0) {
      decltype(state.partition_size) last;
      state.partition_size = state.blocks;
      do {
        last = state.partition_size;
        state.partition_size = state.blocks-Superblock::size_in_blocks(params,
          state.partition_size);
      } while (last != state.partition_size);
    }

    std::uint64_t blocks_required = state.partition_size+
      Superblock::size_in_blocks(params, state.partition_size);
    state.blocks = std::min(state.blocks, blocks_required);
    
    if (state.blocks > free_blocks) {
      std::cerr << "Error: not enough free space." << std::endl;
      return 1;
    }

    pinentry.SETDESC("Enter passphrase for the new partition.");
    Superblock new_partition(params, pinentry.GETPIN(), blocks);
    if (allocated_blocks[new_partition.blocks.front()]) {
      std::cerr << "Error: superblock location already in use." << std::endl;
      return 1;
    }
    allocated_blocks[new_partition.blocks.front()] = true;
    state.blocks--;

    std::vector<std::uint64_t> pool;
    pool.reserve(free_blocks-1);
    for (std::size_t i = 0; i < blocks; i++)
      if (!allocated_blocks[i])
        pool.push_back(i);
    std::shuffle(pool.begin(), pool.end(), std::random_device());
    for (; state.blocks > 0; state.blocks--, state.partition_size--) {
      new_partition.blocks.push_back(pool.back());
      pool.pop_back();
    }
    for (; state.partition_size > 0; state.partition_size--)
      new_partition.blocks.push_back(0);
    new_partition.store(state.device);
    return 0;
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
