#include "pinentry.h"
#include "util.h"
#include <assuan.h>
#include <stdexcept>

Pinentry::Pinentry() {
  gpg_error_t error;
  if ((error = assuan_new(&_pinentry)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
  const char *argv[] = {"pinentry", nullptr};
  if ((error = assuan_pipe_connect(_pinentry, "/usr/bin/pinentry", argv, nullptr,
          nullptr, nullptr, 0)) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
}

static void nodata_command(assuan_context_t ctx,
    const std::string& command, const std::string& data) {
  char buf[ASSUAN_LINELENGTH];
  std::snprintf(buf, ASSUAN_LINELENGTH,
      "%s %s",
      command.c_str(), data.c_str());
  gpg_error_t error;
  if ((error = assuan_transact(ctx, buf,
          nullptr, nullptr,  // data callback
          nullptr, nullptr,  // inquiry callback
          nullptr, nullptr)  // status callback
          ) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
}

Pinentry::~Pinentry() {
  assuan_release(_pinentry);
}

#define Pinentry_NODATA_COMMAND_ARG(cmd) \
  void Pinentry::cmd(const std::string& arg) { \
    nodata_command(_pinentry, #cmd, arg); \
  }
#define Pinentry_NODATA_COMMAND(cmd) \
  void Pinentry::cmd() { \
    nodata_command(_pinentry, #cmd, ""); \
  }

Pinentry_NODATA_COMMAND_ARG(SETDESC)
Pinentry_NODATA_COMMAND_ARG(SETPROMPT)
Pinentry_NODATA_COMMAND_ARG(SETTITLE)
Pinentry_NODATA_COMMAND_ARG(SETOK)
Pinentry_NODATA_COMMAND_ARG(SETCANCEL)
Pinentry_NODATA_COMMAND_ARG(SETNOTOK)
Pinentry_NODATA_COMMAND_ARG(SETERROR)
Pinentry_NODATA_COMMAND(SETQUALITYBAR)
Pinentry_NODATA_COMMAND_ARG(SETQUALITYBAR_TT)
Pinentry_NODATA_COMMAND(MESSAGE)

bool Pinentry::CONFIRM() {
  gpg_error_t error;
  switch (gpg_err_code(error = assuan_transact(_pinentry, "CONFIRM",
        nullptr, nullptr,
        nullptr, nullptr,
        nullptr, nullptr))) {
    case GPG_ERR_NO_ERROR:
      return true;
    case GPG_ERR_NOT_CONFIRMED:
      return false;
    default:
      throw std::system_error(error, gpg_category());
  }
}

static gpg_error_t set_string(void *arg, const void *data, size_t len) {
  std::string *str = reinterpret_cast<std::string*>(arg);
  str->assign(reinterpret_cast<const char*>(data), len);
  return GPG_ERR_NO_ERROR;
}

std::string Pinentry::GETPIN() {
  std::string ret;
  gpg_error_t error;
  if ((error = assuan_transact(_pinentry, "GETPIN",
          set_string, &ret,  // data callback
          nullptr, nullptr,  // inquiry callback
          nullptr, nullptr)  // status callback
        ) != GPG_ERR_NO_ERROR)
    throw std::system_error(error, gpg_category());
  return ret;
}

