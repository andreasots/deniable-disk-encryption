#include "argp-parsers.h"
#include "PBKDF2.h"
#include "crypto.h"
#include "header.h"
#include "util.h"

#include <argp.h>
#include <iostream>
#include "blockdevice.h"

const char* static_doc = "Create an encrypted volume on DEVICE\v\
Default block size: 4194304 bytes or 4 MiB\n\
Default disk cipher: aes-cbc-essiv:sha256\n\
Default disk encryption key length: 256 bits\n\
Default header cipher: AES256\n\
Default hash algorithm: SHA256\n\
Default PBKDF2 iteration time: 1000 ms or one second";

struct State {
  Params params;
  BlockDevice device;
};

error_t init_parsers(int key, char*, argp_state* state) {
  if (key == ARGP_KEY_INIT) {
    state->child_inputs[0] = &reinterpret_cast<State*>(state->input)->params;
    state->child_inputs[1] = &reinterpret_cast<State*>(state->input)->device;
    return 0;
  }
  return ARGP_ERR_UNKNOWN;
}

int main(int argc, char *argv[])
  try {
    State state;
    state.params.block_size = 4 << 20;
    state.params.iters = 1000;
    state.params.key_size = 256/8;
    state.params.hash = "SHA256";
    state.params.device_cipher = "aes-cbc-essiv:sha256";
    state.params.superblock_cipher = "AES256";
    state.params.salt = nonce(16);

    std::string doc = static_doc;
    doc += "\n\nAvaliable hash algorithms:";
    for (auto algo : hash_functions())
      doc += ' ' + algo;
    doc += "\nSome hash algorithms might not be secure.";
    doc += "\n\nAvaliable ciphers for encrypting partition headers:";
    for (auto algo : block_ciphers())
      doc += ' ' + algo;
    doc += "\nSome ciphers might not be secure.";

    auto parsers = new_subparser({"params", "device"});

    argp argp = {nullptr, init_parsers, nullptr, doc.c_str(), parsers.get(),
      nullptr, nullptr};
    argp_parse(&argp, argc, argv, 0, nullptr, &state);

    Hash hash(state.params.hash);

    state.params.iters = PBKDF2::benchmark(hash, state.params.iters);
    state.params.iters /= (state.params.key_size + hash.size()-1)/hash.size();

    state.params.store(state.device);

    return 0;
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
