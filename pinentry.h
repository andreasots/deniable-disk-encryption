#ifndef PINENTRY_H_
#define PINENTRY_H_

#include <assuan.h>
#include <string>

class Pinentry {
 public:
  Pinentry();
  ~Pinentry();

  void SETDESC(const std::string&);
  void SETPROMPT(const std::string&);
  void SETTITLE(const std::string&);
  void SETOK(const std::string&);
  void SETCANCEL(const std::string&);
  void SETNOTOK(const std::string&);
  void SETERROR(const std::string&);
  void SETQUALITYBAR();
  void SETQUALITYBAR_TT(const std::string&);
  std::string GETPIN();
  bool CONFIRM();
  void MESSAGE();

 private:
  assuan_context_t _pinentry;
};

#endif  // PINENTRY_H_
