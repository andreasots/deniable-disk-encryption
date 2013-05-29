#ifndef ARGP_PARSERS_H_
#define ARGP_PARSERS_H_

#include <argp.h>
#include <memory>
#include <vector>

std::unique_ptr<argp_child[]> new_subparser(const std::vector<std::string>&);

#endif
