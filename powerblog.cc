#define H2O_USE_EPOLL 1
#include "h2o.h"
#include <nlohmann/json.hpp>
#include "sqlite_orm.h"
#include <iostream>
#include <signal.h>
#include <stdexcept>

using namespace std;

struct PBLogEvent
{
  unsigned int id;
  double timestamp;
  std::string content;
  std::string originator;
  int channel;
};

auto prepareDatabase()
{
  using namespace sqlite_orm;
  auto storage = make_storage
    ("powerblog.sqlite",
     make_table("events",
                make_column("id", &PBLogEvent::id, autoincrement(), primary_key()),
                make_column("timestamp", &PBLogEvent::timestamp),
                make_column("content", &PBLogEvent::content),
                make_column("originator", &PBLogEvent::originator),
                make_column("channel", &PBLogEvent::channel)
                ));

  storage.sync_schema();
  auto eventCount = storage.count<PBLogEvent>();
  cout<<"On starteup, there were "<<eventCount<<" events"<<endl;
  return storage;
}

using DBType=decltype(prepareDatabase());

DBType* g_db;

static h2o_accept_ctx_t g_accept_ctx;
void setupSSL()
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  g_accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  g_accept_ctx.expect_proxy_line = 0; // makes valgrind happy

  SSL_CTX_set_options(g_accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_ecdh_auto(g_accept_ctx.ssl_ctx, 1);

  /*
   /etc/letsencrypt/live/live.powerdns.org/fullchain.pem
   Your key file has been saved at:
   /etc/letsencrypt/live/live.powerdns.org/privkey.pem
  */
  const char cert_file[] = "/etc/letsencrypt/live/live.powerdns.org/fullchain.pem";
  const char key_file[]="/etc/letsencrypt/live/live.powerdns.org/privkey.pem";
    
  
/* load certificate and private key */
  if(SSL_CTX_use_certificate_chain_file(g_accept_ctx.ssl_ctx, cert_file) != 1) {
    fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
    throw std::runtime_error("certificate key");
  }
  
  if(SSL_CTX_use_PrivateKey_file(g_accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
    throw std::runtime_error("private key");
  }

  char ciphers[]="DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK";
  if(SSL_CTX_set_cipher_list(g_accept_ctx.ssl_ctx, ciphers) != 1) {
    fprintf(stderr, "ciphers could not be set: %s\n", ciphers);
    throw std::runtime_error("algorithms");
  }
}

static void emitAllEventsSince(h2o_req_t* req, unsigned int since)
{
  cout<<"Going to emit all events since "<<since<<endl;
  nlohmann::json allEvents;
  allEvents["msgs"] = nlohmann::json::array();

  using namespace sqlite_orm;
  auto events = g_db->get_all<PBLogEvent>(where(c(&PBLogEvent::id) > since));
  unsigned int maxID=0;
  cout<<" got "<<events.size()<<" events"<<endl;
  for(auto &e : events) {
    nlohmann::json event;
    event = e.content;
    allEvents["msgs"].push_back(event);
    if(e.id > maxID)
      maxID = e.id;
  }
  allEvents["last"]=maxID;
  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
    NULL, H2O_STRLIT("application/json"));
  std::string str = allEvents.dump();
  h2o_send_inline(req, str.c_str(), str.size());
}


static int allEventsHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
    return -1;

  auto eventCount = g_db->count<PBLogEvent>();
  cout<<"There are "<<eventCount<<" events"<<endl;

  emitAllEventsSince(req, 0);
  
  return 0;
}

std::map<h2o_req_t*, unsigned int> g_waiters;

static int newEventsHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
    return -1;

  string path(req->path.base, req->path.len);

  if(auto pos = path.find("?since="); pos != string::npos) {
    uint32_t since = atoi(path.c_str() + pos + 7);
    cout<<"Wants updates since " << since <<", path: "<<path<<endl;

    using namespace sqlite_orm;
    auto count = g_db->count<PBLogEvent>(where(c(&PBLogEvent::id) > since));
    if(count > 0) {
      cout<<" have "<<count<<" events available right now"<<endl;
      emitAllEventsSince(req, since);
    }
    else {
      cout<<" nothing available, putting on wait list"<<endl;
      g_waiters[req]=since;
    }
    return 0;
  }
  h2o_send_error_400(req, "Bad Request", "PowerBlog could not understand your query", 0);
  return 0;
}


static int sendHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
    return -1;

  std::string content(req->entity.base, req->entity.len);
  PBLogEvent pbl;
  pbl.id = 0;
  pbl.timestamp = time(0);
  pbl.content = content;
  pbl.originator = "unknown";
  pbl.channel = 1;

  g_db->insert(pbl);

  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
    NULL, H2O_STRLIT("application/json"));
  nlohmann::json ret;
  ret["status"]="ok";
  std::string str = ret.dump();
  h2o_send_inline(req, str.c_str(), str.size());

  cout<<"There are "<<g_waiters.size()<< " waiters that need to hear '"<<content<<"'"<<endl;
  for(auto iter = g_waiters.begin(); iter != g_waiters.end(); ) {
    auto nreq = iter->first;
    auto since = iter->second;
    iter = g_waiters.erase(iter);
    emitAllEventsSince(nreq, since);
  }
  cout<<"There are "<<g_waiters.size()<< " waiters"<<endl;
  return 0;
  
}


int main()
try
{
  signal(SIGPIPE, SIG_IGN);
  g_db = new DBType(prepareDatabase());
  
  h2o_globalconf_t config;
  h2o_context_t ctx;

  
  h2o_config_init(&config);
  h2o_hostconf_t* hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

  h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, "/allEvents", 0);
  h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = allEventsHandler;

  pathconf = h2o_config_register_path(hostconf, "/newEvents", 0);
  handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = newEventsHandler;

  pathconf = h2o_config_register_path(hostconf, "/sendEvent", 0);
  handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = sendHandler;

  pathconf = h2o_config_register_path(hostconf, "/", 0);
  h2o_file_register(pathconf, "html", NULL, NULL, 0);
  
  h2o_context_init(&ctx, h2o_evloop_create(), &config);
  
  g_accept_ctx.ctx = &ctx;
  g_accept_ctx.hosts = config.hosts;

  setupSSL();
  
  struct sockaddr_in addr;
  int fd, reuseaddr_flag = 1;
  h2o_socket_t *sock;
  
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(0);
  addr.sin_port = htons(443);
  
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
      bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
    throw runtime_error("Unable to bind to socket: "+string(strerror(errno)));
  }

  sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  h2o_socket_read_start(sock, [](h2o_socket_t *listener, const char *err) {
      if (err != NULL) {
        return;
      }
      h2o_socket_t *sock;
      
      if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
      h2o_accept(&g_accept_ctx, sock);
    });
  while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
    ;
}
catch(std::exception& e)
{
  cerr<<"PowerBlog exiting: "<<e.what()<<endl;
}
