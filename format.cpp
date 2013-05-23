#include "PBKDF2.h"
#include "crypto.h"
#include "header.h"
#include "util.h"

#include <openssl/rand.h>

#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <chrono>

std::size_t block_size = 4 << 20; // 4 MiB
std::string cipher = "aes-cbc-essiv:sha256";
std::string hash_algo = "sha256";
std::size_t iter_time = 1000;
std::size_t key_size = 256;

option options[] = {
  {"block-size", required_argument, nullptr, 'b'},
  {"cipher", required_argument, nullptr, 'c'},
  {"hash", required_argument, nullptr, 'H'},
  {"iter-time", required_argument, nullptr, 'i'},
  {"key-size", required_argument, nullptr, 's'},
  {"help", no_argument, nullptr, 'h'},
  {nullptr, 0, nullptr, 0}
};

void print_help(const std::string& name, std::ostream& out) {
  out << name << " [OPTION]... DEVICE" << std::endl;
  out << "Create a encrypted volume on DEVICE" << std::endl;
  out << std::endl;
  out << "Mandatory arguments to long options are mandatory for short options";
  out << " too." << std::endl;
  out << "  -b, --block-size=bytes    Size of blocks in bytes. Default: " << (4 << 20) << std::endl;
  out << "  -c, --cipher=STRING       The cipher used to encrypt the disk (see /proc/crypto). Default: aes-cbc-essiv:sha256" << std::endl;
  out << "  -H, --hash=STRING         The hash used to create the encryption key from the passphrase. Default: sha256" << std::endl;
  out << "  -i, --iter-time=ms        PBKDF2 iteration time (in ms). Default: 1000" << std::endl;
  out << "  -s, --key-size=bits       Key size in bits. Must be a multiple of 8. Default: 256" << std::endl;
  out << "  -h, --help                Display this message and exit." << std::endl;
  out << std::endl;
  out << "Available hash functions:";
  for(auto name : hash_functions())
    out << ' ' << name;
  out << std::endl;
  out << "Some hash functions might not be secure." << std::endl;
}

template <class T> T from_string(const std::string& str) {
  T ret;
  std::stringstream(str) >> ret;
  return ret;
}

void parse_args(int argc, char *argv[]) {
  int option_index, c;
  while((c = getopt_long(argc, argv, "b:c:H:hi:s:", options, &option_index)) != -1)
    switch(c) {
      case 'b':
        block_size = from_string<std::size_t>(optarg);
        break;
      case 'c':
        cipher = optarg;
        break;
      case 'H':
        hash_algo = optarg;
        break;
      case 'i':
        iter_time = from_string<std::size_t>(optarg);
        break;
      case 's':
        key_size = from_string<std::size_t>(optarg);
        if (key_size % 8 != 0)
          throw std::runtime_error("Key size must be a multiple of 8");
        break;
      case 'h':
        print_help(argv[0], std::cout);
        exit(0);
      case '?':
        // getopt has already printed out an error message
        throw std::runtime_error(std::string());
      default:
        throw std::runtime_error("Unhandled argument");
    }
}

int main(int argc, char *argv[]) {
  try {
    parse_args(argc, argv);
  } catch(const std::runtime_error& e) {
    if (e.what() != std::string())
      std::cerr << "Error: " << e.what() << std::endl;
    std::cerr << "Try '" << argv[0] << " --help' for more information." << std::endl;
    return 1;
  }
  if (argc - optind != 1) {
    std::cerr << argv[0] << " requires a device path an argument" << std::endl;
    std::cerr << "Try '" << argv[0] << " --help' for more information." << std::endl;
    return 1;
  }

  Hash hash(hash_algo);

  key_size /= 8;
  auto iter = PBKDF2::benchmark(hash, iter_time);
  iter /= (key_size + hash.size()-1)/hash.size();

  Params params;
  params.block_size = block_size;
  params.iters = iter;
  params.key_size = key_size;
  params.cipher = cipher;
  params.hash = hash_algo;
  params.salt = nonce(16);
  try {
    params.store(argv[optind]);
  } catch(const std::exception& e) {
    std::cerr << "Device " << argv[optind] << " doesn't exist or access ";
    std::cerr << "denied." << std::endl;
    return 1;
  }
  
  return 0;
}
