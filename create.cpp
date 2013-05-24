#include "header.h"
#include "pinentry.h"
#include <getopt.h>
#include <iostream>
#include <cstdlib>

option options[] = {
  {"help", no_argument, nullptr, 'h'},
  {nullptr, 0, nullptr, 0}
};

void print_help(const std::string& name, std::ostream& out) {
  out << name << " [OPTION]... DEVICE" << std::endl;
  out << "Create a new partition on DEVICE." << std::endl;
  out << std::endl;
  out << "  -h, --help    Print this message and exit." << std::endl;
}

void parse_args(int argc, char *argv[]) {
  int option_index, c;
  while ((c = getopt_long(argc, argv, "h", options, &option_index)) != -1)
    switch (c) {
      case 'h':
        print_help(argv[0], std::cout);
        std::exit(0);
      case '?':
        throw std::runtime_error(std::string());
      default:
        throw std::runtime_error("Unhandled argument");
    }
}

int main(int argc, char *argv[]) {
  try {
  } catch (const std::exception& e) {
    if (e.what() != std::string())
      std::cerr << "Error: " << e.what() << std::endl;
    std::cerr << "Try '" << argv[0] << " --help' for more information." << std::endl;
    return 1;
  }
  if (argc - optind != 1) {
    std::cerr << argv[0] << " required a device path as an argument." << std::endl;
    std::cerr << "Try '" << argv[0] << " --help' for more information." << std::endl;
    return 1;
  }
  
  std::fstream device(argv[optind], std::ios::in | std::ios::out);
  Params params;
  try {
    params.load(device);
  } catch(const std::exception& e) {
    std::cerr << "Error: Header corrupt." << std::endl;
    return 1;
  }
  std::uint64_t blocks = device.seekg(0, std::ios::end).tellg()/params.block_size;
  
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
