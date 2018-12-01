#include "h2o-pp.hh"
#include "comboaddress.hh"

using namespace std;

H2OWebserver::H2OWebserver(const std::string_view hostname, int port)
{
  memset(&d_ctx, 0, sizeof(d_ctx));
  memset(&d_config, 0, sizeof(d_config));
  
  h2o_config_init(&d_config);

  d_hostconf = addHost(hostname, port); // this is the default host

  h2o_context_init(&d_ctx, h2o_evloop_create(), &d_config);
}

h2o_hostconf_t* H2OWebserver::addHost(const std::string_view hostname, int port)
{
  return h2o_config_register_host(&d_config, h2o_iovec_init(&hostname[0], hostname.length()), port);
}

void H2OWebserver::addListener(const ComboAddress& addr, h2o_accept_ctx_t* accept_ctx)
{
  int one = 1;

  int fd;
  if ((fd = socket(addr.sin4.sin_family, SOCK_STREAM, 0)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
      (addr.sin4.sin_family == AF_INET6 && (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) != 0)) ||
      bind(fd, (struct sockaddr *)&addr, addr.getSocklen()) != 0 || listen(fd, SOMAXCONN) != 0) {
    throw runtime_error("Unable to bind to socket: "+string(strerror(errno)));
  }

  h2o_socket_t *sock = h2o_evloop_socket_create(d_ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  sock->data = accept_ctx;

  h2o_socket_read_start(sock, [](h2o_socket_t *listener, const char *err) {
      if (err != NULL) {
        return;
      }
      h2o_socket_t *sock;
      
      if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
      h2o_accept((h2o_accept_ctx_t*)listener->data, sock);
    });

}

void H2OWebserver::addHandler(const std::string& path, nhandler_t* func, h2o_hostconf_t* host)
{
  h2o_pathconf_t *pathconf = h2o_config_register_path(host ? host : d_hostconf, &path[0], 0);

  h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = func;
}

void H2OWebserver::addHandler(const std::string& path, shandler_t* func, h2o_hostconf_t* host)
{
  h2o_pathconf_t *pathconf = h2o_config_register_path(host ? host : d_hostconf, &path[0], 0);

  MultiHandler *handler = (MultiHandler*)h2o_create_handler(pathconf, sizeof(*handler));
  handler->shandler = func;
  handler->handler.on_req=H2OWebserver::mwrapper;
}

void H2OWebserver::addHandler(const std::string& path, jhandler_t* func, h2o_hostconf_t* host)
{
  h2o_pathconf_t *pathconf = h2o_config_register_path(host ? host : d_hostconf, &path[0], 0);
  MultiHandler *handler = (MultiHandler*)h2o_create_handler(pathconf, sizeof(*handler));
  handler->jhandler = func;
  handler->handler.on_req=H2OWebserver::mwrapper;
}


int H2OWebserver::mwrapper(h2o_handler_t* handler, h2o_req_t* req)
{
  MultiHandler* shandler = (MultiHandler*)handler;
  string mimetype, content;
  if(shandler->shandler) {
    std::tie(mimetype,content) = shandler->shandler(handler, req);
  }
  else {
    mimetype = "application/json";
    content = shandler->jhandler(handler,req).dump();
  }
  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                 NULL, mimetype.c_str(), mimetype.size());
  h2o_send_inline(req, content.c_str(), content.length());
  return 0;
}

h2o_accept_ctx_t* H2OWebserver::addContext()
{
  auto accept_ctx = new h2o_accept_ctx_t();
  memset(accept_ctx, 0, sizeof(h2o_accept_ctx_t));
  accept_ctx->ctx = &d_ctx;
  accept_ctx->hosts = d_config.hosts;
  return accept_ctx;
}


h2o_accept_ctx_t* H2OWebserver::addSSLContext(const std::string_view certificate, const std::string_view key, const std::string_view ciphers)
{
  auto accept_ctx = new h2o_accept_ctx_t();
  memset(accept_ctx, 0, sizeof(h2o_accept_ctx_t));
  accept_ctx->ctx = &d_ctx;
  accept_ctx->hosts = d_config.hosts;
  
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  accept_ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

  SSL_CTX_set_options(accept_ctx->ssl_ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_ecdh_auto(accept_ctx->ssl_ctx, 1);

  const char* cert_file = &certificate[0];
  const char* key_file= &key[0];
    
  
/* load certificate and private key */
  if(SSL_CTX_use_certificate_chain_file(accept_ctx->ssl_ctx, cert_file) != 1) {
    throw std::runtime_error("certificate file");
  }
  
  if(SSL_CTX_use_PrivateKey_file(accept_ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    throw std::runtime_error("private file");
  }
  // "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK"
  if(SSL_CTX_set_cipher_list(accept_ctx->ssl_ctx, !ciphers.empty() ? &ciphers[0] : "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256" ) != 1) {
    throw std::runtime_error("algorithms");
  }

  h2o_ssl_register_alpn_protocols(accept_ctx->ssl_ctx, h2o_http2_alpn_protocols);
  return accept_ctx;
}

void H2OWebserver::runLoop()
{
  while (h2o_evloop_run(d_ctx.loop, INT32_MAX) == 0)
    ;
}


void H2OWebserver::addDirectory(const std::string_view path, const std::string_view directory, h2o_hostconf_t* hconf)
{
  h2o_pathconf_t* pathconf = h2o_config_register_path(hconf ? hconf : d_hostconf, &path[0], 0);
  h2o_file_register(pathconf, &directory[0], NULL, NULL, 0);
}

std::string_view convert(const h2o_iovec_t& vec)
{
  return std::string_view(vec.base, vec.len);
}
