#include "blockdevice.h"
#include "header.h"
#include "pinentry.h"
#include "PBKDF2.h"
#include "argp-parsers.h"
#include <argp.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <libdevmapper.h>

const char* doc = "Open an encrypted partition on DEVICE";

argp_option options[] = {
  {"name", 'n', "NAME", 0, "NAME is the device to create under /dev/mapper", 0},
  {nullptr, 0, nullptr, 0, nullptr, 0}
};

struct State {
  BlockDevice device;
  std::string name;
};

error_t init_parsers(int key, char* arg, argp_state* state) {
  State& args = *reinterpret_cast<State*>(state->input);
  switch (key) {
    case 'n':
      args.name = arg;
      break;
   case ARGP_KEY_INIT:
      state->child_inputs[0] = &args.device;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

std::string hex(const std::string& str) {
  std::stringstream ss;
  ss << std::hex;
  for (char c : str)
    ss << std::setw(2) << std::setfill('0')
      << static_cast<int>(static_cast<unsigned char>(c));
  return ss.str();
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

    Pinentry pinentry;
    pinentry.SETDESC("Enter passphrases for a partition on this volume.");
    pinentry.SETPROMPT("Passphrase:");
    auto passphrase = pinentry.GETPIN();
    Superblock superblock(params, passphrase, blocks);
    try {
      superblock.load(state.device);
    } catch(...) {
      std::cerr << "Error: No partition found for that passphrase." << std::endl;
    }
    Hash hash(params.hash);
    std::string key = PBKDF2::PBKDF2(hash, passphrase, params.salt,
        params.iters, params.key_size);

    if (state.name.empty()) {
      hash.reset();
      hash.update(key);
      state.name = hex(hash.digest().substr(8));
    }

    dm_task* dmt;
    if (!(dmt = dm_task_create(DM_DEVICE_CREATE)));
    dm_task_set_name(dmt, state.name.c_str());
    std::uint64_t offset = 0;
    for (auto block = superblock.blocks.begin()+superblock.offset;
        block != superblock.blocks.end(); block++, offset += params.block_size) {
      if (*block != 0) {
        std::stringstream ss;
        ss << params.device_cipher << " " << hex(key) << " 0 ";
        ss << state.device.major() << ":" << state.device.minor() << " ";
        ss << (*block)*params.block_size/512;
        dm_task_add_target(dmt, offset/512, params.block_size/512, "crypt", ss.str().c_str());
      } else {
        dm_task_add_target(dmt, offset/512, params.block_size/512, "error", "");
      }
    }
    dm_task_run(dmt);
    dm_task_destroy(dmt);

    return 0;
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
