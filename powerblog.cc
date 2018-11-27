#define H2O_USE_EPOLL 1
#include "h2o.h"
#include <nlohmann/json.hpp>
#include "sqlite_orm.h"
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include "comboaddress.hh"
#include <thread>
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
  cout<<"On startup, there were "<<eventCount<<" events"<<endl;
  return storage;
}

using DBType=decltype(prepareDatabase());

DBType* g_db;


void setupSSL(h2o_accept_ctx_t& accept_ctx)
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  accept_ctx.expect_proxy_line = 0; // makes valgrind happy

  SSL_CTX_set_options(accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_ecdh_auto(accept_ctx.ssl_ctx, 1);

  const char cert_file[] = "./fullchain.pem";
  const char key_file[]="./privkey.pem";
    
  
/* load certificate and private key */
  if(SSL_CTX_use_certificate_chain_file(accept_ctx.ssl_ctx, cert_file) != 1) {
    fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
    throw std::runtime_error("certificate key");
  }
  
  if(SSL_CTX_use_PrivateKey_file(accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
    throw std::runtime_error("private key");
  }

  char ciphers[]="DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK";
  if(SSL_CTX_set_cipher_list(accept_ctx.ssl_ctx, ciphers) != 1) {
    fprintf(stderr, "ciphers could not be set: %s\n", ciphers);
    throw std::runtime_error("algorithms");
  }
}

std::map<h2o_req_t*, unsigned int> g_waiters;

static void emitAllEventsSince(h2o_req_t* req, unsigned int since, bool mustReload=false)
{
  cout<<"Going to emit all events since "<<since<<endl;
  nlohmann::json allEvents;
  allEvents["msgs"] = nlohmann::json::array();

  if(!mustReload) {
    using namespace sqlite_orm;
    auto events = g_db->get_all<PBLogEvent>(where(c(&PBLogEvent::id) > since),order_by(&PBLogEvent::id) );
    unsigned int maxID=0;
    cout<<" got "<<events.size()<<" events"<<endl;
    for(auto &e : events) {
      nlohmann::json event;
      event["id"]=e.id;
      event["message"]=e.content;
      event["timestamp"]=e.timestamp;
      event["channel"]=e.channel;
      event["originator"]=e.originator;
      allEvents["msgs"].push_back(event);
      if(e.id > maxID)
        maxID = e.id;
    }
    allEvents["last"]=maxID;
  }

  if(!since)
    allEvents["restart"]=true;
  if(mustReload)
    allEvents["reload"]=true;
  
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

bool isAdmin(h2o_req_t* req)
{
  string hdr;
  string val;
  for (unsigned int i = 0; i != req->headers.size; ++i) {
    hdr.assign(req->headers.entries[i].name->base, req->headers.entries[i].name->len);
    // cookie: name=ahu
    if(hdr=="cookie") {
      val.assign(req->headers.entries[i].value.base, req->headers.entries[i].value.len);
      if(val.find("adminpw=123456789") != string::npos)
        return true;
    }
  }

  return false;
}

static int newEventsHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
    return -1;

  
  string path(req->path.base, req->path.len);
  h2o_socket_t* sock = req->conn->callbacks->get_socket(req->conn);
  ComboAddress remote;
  h2o_socket_getpeername(sock, (struct sockaddr*)&remote);

  if(auto pos = path.find("?since="); pos != string::npos) {
    uint32_t since = atoi(path.c_str() + pos + 7);
    cout<<remote.toString()<<" wants updates since " << since <<", path: "<<path<<endl;

    using namespace sqlite_orm;
    auto count = g_db->count<PBLogEvent>(where(c(&PBLogEvent::id) > since));
    if(count > 0) {
      cout<<" have "<<count<<" events available right now"<<endl;
      emitAllEventsSince(req, since);
    }
    else {
      g_waiters[req]=since;
      cout<<" nothing available, putting on wait list (" << g_waiters.size()<<")"<<endl;
      h2o_req_t** parent = (h2o_req_t**)h2o_mem_alloc_shared(&req->pool, sizeof(h2o_req_t*), [](void* _self) {
          h2o_req_t** r = (h2o_req_t**)_self;
          cout << "Connection "<<(void*)*r<<" went away, we still had a waiter on it "<<g_waiters.count(*r)<<endl;
          g_waiters.erase(*r);
          for(const auto& w : g_waiters)
            cout <<"  "<<(void*)w.first<<endl;
        });
      *parent = req;
    }
    return 0;
  }
  h2o_send_error_400(req, "Bad Request", "PowerBlog could not understand your query", 0);
  return 0;
}


static int deleteHandler(h2o_handler_t* handler, h2o_req_t* req)
try
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
    return -1;

  if(!isAdmin(req)) {
    h2o_send_error_400(req, "Bad Request", "PowerBlog could not understand your query", 0);
    return 0;
  }
  
  std::string content(req->entity.base, req->entity.len);
  
  g_db->remove<PBLogEvent>(atoi(content.c_str()));

  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                 NULL, H2O_STRLIT("application/json"));
  nlohmann::json ret;
  ret["status"]="ok";
  std::string str = ret.dump();
  h2o_send_inline(req, str.c_str(), str.size());
  
  cout<<"There are "<<g_waiters.size()<< " waiters that need to hear about our delete of id "<<content<<endl;
  for(auto iter = g_waiters.begin(); iter != g_waiters.end(); ) {
    auto nreq = iter->first;
    cout<<"  Erasing "<<(void*)iter->first<<endl;
    iter = g_waiters.erase(iter);
    emitAllEventsSince(nreq, 0);
  }
  cout<<"There are "<<g_waiters.size()<< " waiters"<<endl;
  return 0;
}
catch(std::exception& e)
{
  cerr<<"sendEvent error: "<<e.what()<<endl;
  h2o_send_error_400(req, "Bad Request", "could not parse your request", 0);
  return 0;
}

static int reloadHandler(h2o_handler_t* handler, h2o_req_t* req)
try
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
    return -1;

  if(!isAdmin(req)) {
    h2o_send_error_400(req, "Bad Request", "PowerBlog could not understand your query", 0);
    return 0;
  }
  
  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                 NULL, H2O_STRLIT("application/json"));
  nlohmann::json ret;
  ret["status"]="ok";
  std::string str = ret.dump();
  h2o_send_inline(req, str.c_str(), str.size());
  
  cout<<"There are "<<g_waiters.size()<< " waiters that need to hear about reload request"<<endl;
  for(auto iter = g_waiters.begin(); iter != g_waiters.end(); ) {
    auto nreq = iter->first;
    cout<<"  Erasing "<<(void*)iter->first<<endl;
    iter = g_waiters.erase(iter);
    emitAllEventsSince(nreq, 0, true); // triggers reload
  }
  cout<<"There are "<<g_waiters.size()<< " waiters"<<endl;
  return 0;
}
catch(std::exception& e)
{
  cerr<<"reload error: "<<e.what()<<endl;
  h2o_send_error_400(req, "Bad Request", "could not parse your request", 0);
  return 0;
}


static int sendHandler(h2o_handler_t* handler, h2o_req_t* req)
try
{
  if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
    return -1;

  std::string content(req->entity.base, req->entity.len);
  auto msg = nlohmann::json::parse(content);
  PBLogEvent pbl;
  pbl.id = 0;
  pbl.timestamp = time(0);
  pbl.content = msg["msg"];
  pbl.originator = msg["originator"];
  pbl.channel = msg["channel"].get<int>();


  if(pbl.channel== 1 && !isAdmin(req)) {
    h2o_send_error_400(req, "Bad Request", "PowerBlog could not understand your query", 0);
    return 0;
  }
  
  g_db->insert(pbl);

  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                 NULL, H2O_STRLIT("application/json"));
  nlohmann::json ret;
  ret["status"]="ok";
  std::string str = ret.dump();
  h2o_send_inline(req, str.c_str(), str.size());
  
  cout<<"There are "<<g_waiters.size()<< " waiters that need to hear about "<<content<<endl;
  for(auto iter = g_waiters.begin(); iter != g_waiters.end(); ) {
    auto nreq = iter->first;
    auto since = iter->second;
    cout<<"  Erasing "<<(void*)iter->first<<endl;
    iter = g_waiters.erase(iter);
    emitAllEventsSince(nreq, since);
  }
  cout<<"There are "<<g_waiters.size()<< " waiters"<<endl;
  return 0;
}
catch(std::exception& e)
{
  cerr<<"sendEvent error: "<<e.what()<<endl;
  h2o_send_error_400(req, "Bad Request", "could not parse your request", 0);
  return 0;
}


void forwarderServer()
{
  h2o_globalconf_t config;
  h2o_context_t ctx;
  h2o_accept_ctx_t accept_ctx;

  h2o_config_init(&config);
  h2o_hostconf_t* hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

  h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, "/", 0);
  h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = [](h2o_handler_t* handler, h2o_req_t* req)
    {
      h2o_send_redirect(req, 301, "Moved Permanently", H2O_STRLIT("https://live.powerdns.org/"));
      return 0;
    };
  
  h2o_context_init(&ctx, h2o_evloop_create(), &config);
  
  accept_ctx.ctx = &ctx;
  accept_ctx.hosts = config.hosts;
  accept_ctx.ssl_ctx=0;
  
  struct sockaddr_in addr;
  int fd, reuseaddr_flag = 1;
  h2o_socket_t *sock;
  
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(0);
  addr.sin_port = htons(80);
  
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
      bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
    throw runtime_error("Unable to bind to socket: "+string(strerror(errno)));
  }

  sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  sock->data = &accept_ctx;
  h2o_socket_read_start(sock, [](h2o_socket_t *listener, const char *err) {
      if (err != NULL) {
        return;
      }
      h2o_socket_t *sock;
      
      if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
      h2o_accept((h2o_accept_ctx_t*)listener->data, sock);
    });
  while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
    ;

}

int main()
try
{
  signal(SIGPIPE, SIG_IGN);
  g_db = new DBType(prepareDatabase());
  
  h2o_globalconf_t config;
  h2o_context_t ctx;
  h2o_accept_ctx_t accept_ctx;
  
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

  pathconf = h2o_config_register_path(hostconf, "/deleteEvent", 0);
  handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = deleteHandler;

  pathconf = h2o_config_register_path(hostconf, "/reloadClients", 0);
  handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = reloadHandler;

  
  pathconf = h2o_config_register_path(hostconf, "/", 0);
  h2o_file_register(pathconf, "html", NULL, NULL, 0);
  
  h2o_context_init(&ctx, h2o_evloop_create(), &config);
  
  accept_ctx.ctx = &ctx;
  accept_ctx.hosts = config.hosts;

  setupSSL(accept_ctx);
  
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
  sock->data = &accept_ctx;
  h2o_socket_read_start(sock, [](h2o_socket_t *listener, const char *err) {
      if (err != NULL) {
        return;
      }
      h2o_socket_t *sock;
      
      if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
      h2o_accept((h2o_accept_ctx_t*)listener->data, sock);
    });

  std::thread fwthread(forwarderServer);
  fwthread.detach();
  
  while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
    ;
}
catch(std::exception& e)
{
  cerr<<"PowerBlog exiting: "<<e.what()<<endl;
}
