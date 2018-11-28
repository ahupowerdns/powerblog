#pragma once
#define H2O_USE_EPOLL 1
#include "h2o.h"
#include <string>
#include <functional>
#include "comboaddress.hh"

struct H2OWebserver
{
  explicit H2OWebserver(const std::string_view hostname="default");
  typedef int handler_t(h2o_handler_t*, h2o_req_t*);
  h2o_hostconf_t* addHost(const std::string_view hostname);
  void addHandler(const std::string& path, handler_t* func, h2o_hostconf_t* hconf=0);
  h2o_accept_ctx_t* getSSLContext(const std::string_view certificate, const std::string_view key, const std::string_view ciphers);
  h2o_accept_ctx_t* getContext();
  void addListener(const ComboAddress& addr, h2o_accept_ctx_t*);
  void runLoop();
  
  h2o_globalconf_t d_config;
  h2o_context_t d_ctx;
  h2o_hostconf_t* d_hostconf;
};
