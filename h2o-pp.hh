#pragma once
#define H2O_USE_EPOLL 1
#include "h2o.h"
#include <string>
#include <functional>
#include "comboaddress.hh"
#include <nlohmann/json.hpp>

/* A non-wrapper for libh2o. It is not a wrapper since it does not change any semantics nor hide any internals. 
   It does however make life easier for you and saves a lot of typing.
*/

struct H2OWebserver
{
  /** Instantiates the basic webserver, with no sockets or accept contexts yet.
      The provided hostname and port are the name of the first host defined. 
      The default port value 65535 indicates to h2o that this is on port 80 or 443 
      depending on the protocol */
  explicit H2OWebserver(const std::string_view hostname="default", int port=65535);
  typedef int nhandler_t(h2o_handler_t*, h2o_req_t*);

  typedef std::pair<std::string, std::string> shandler_t(h2o_handler_t*, h2o_req_t*);
  typedef nlohmann::json jhandler_t(h2o_handler_t*, h2o_req_t*);
  
  //! Optional, used to add additional host names to the server, which each can have their own handlers
  h2o_hostconf_t* addHost(const std::string_view hostname, int port=65535);

  //! Add a handler function to a path. Defaults to adding it to the default host. 
  void addHandler(const std::string& path, nhandler_t* func, h2o_hostconf_t* hconf=0);

  //! Add a handler function to a path. Defaults to adding it to the default host. 
  void addHandler(const std::string& path, shandler_t* func, h2o_hostconf_t* hconf=0);

  //! Add a handler function to a path. Defaults to adding it to the default host. 
  void addHandler(const std::string& path, jhandler_t* func, h2o_hostconf_t* hconf=0);

  
  //! Add a directory to be served on a path. Defaults to adding it to the default host.
  void addDirectory(const std::string_view path, const std::string_view directory, h2o_hostconf_t* hconf=0);

  //! Call this to add a TLS context. Returns an accept context that can be used with addListener
  h2o_accept_ctx_t* addSSLContext(const std::string_view certificate, const std::string_view key, const std::string_view ciphers="");

  //! Call this to add a plaintext context. Returns an accept context that can be used with addListener
  h2o_accept_ctx_t* addContext();

  //! Create a socket on an IP address & add it to the context
  void addListener(const ComboAddress& addr, h2o_accept_ctx_t*);

  //! Let the server run
  void runLoop();
  
  h2o_globalconf_t d_config;
  h2o_context_t d_ctx;
  h2o_hostconf_t* d_hostconf;

  struct MultiHandler
  {
    h2o_handler_t handler;
    shandler_t* shandler{nullptr};
    jhandler_t* jhandler{nullptr};
  };
  static int mwrapper(h2o_handler_t*, h2o_req_t*);
  
};

std::string_view convert(const h2o_iovec_t& vec);
