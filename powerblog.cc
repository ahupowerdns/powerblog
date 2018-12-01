#include "h2o-pp.hh"

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
  for (unsigned int i = 0; i != req->headers.size; ++i) {
    std::string_view hdr(req->headers.entries[i].name->base, req->headers.entries[i].name->len);

    // cookie: name=ahu
    if(hdr=="cookie") {
      string_view val = convert(req->headers.entries[i].value);
      if(val.find("adminpw=megageheim") != string::npos)
        return true;
    }
  }
  
  return false;
}

static int newEventsHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  if(convert(req->method) != "GET")
    return -1;
  
  string_view path = convert(req->path);
  h2o_socket_t* sock = req->conn->callbacks->get_socket(req->conn);
  ComboAddress remote;
  h2o_socket_getpeername(sock, (struct sockaddr*)&remote);

  if(auto pos = path.find("?since="); pos != string::npos) {
    uint32_t since = atoi(&path.at(pos + 7));
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


int main()
try
{
  signal(SIGPIPE, SIG_IGN);
  g_db = new DBType(prepareDatabase());

  H2OWebserver h2s("live.powerdns.org", 443);

  h2s.addHandler("/allEvents", allEventsHandler);
  h2s.addHandler("/newEvents", newEventsHandler);
  h2s.addHandler("/sendEvent", sendHandler);
  h2s.addHandler("/deleteEvent", deleteHandler);
  h2s.addHandler("/reloadClients", reloadHandler);
  h2s.addDirectory("/", "./html/");

  auto plaintext = h2s.addHost("live.powerdns.org", 80);
  h2s.addHandler("/", [](h2o_handler_t* handler, h2o_req_t* req)
                 {
                   std::string_view path=convert(req->path);
                   cout << path << endl;
                   h2o_send_redirect(req, 301, "Moved Permanently", H2O_STRLIT("https://live.powerdns.org/"));
                   return 0;
                 }, plaintext); 
  
  auto sslactx = h2s.addSSLContext("./fullchain.pem", "./privkey.pem");

  h2s.addListener(ComboAddress("0.0.0.0", 443),sslactx);
  h2s.addListener(ComboAddress("::", 443), sslactx);

  auto actx = h2s.addContext();
  h2s.addListener(ComboAddress("0.0.0.0", 80), actx);
  h2s.addListener(ComboAddress("::", 80), actx);
  
  h2s.runLoop();
}
catch(std::exception& e)
{
  cerr<<"PowerBlog exiting: "<<e.what()<<endl;
}
