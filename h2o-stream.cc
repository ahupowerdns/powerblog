#include "h2o-pp.hh"

#include <nlohmann/json.hpp>
#include "sqlite_orm.h"
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include "comboaddress.hh"
#include <thread>
using namespace std;

struct Event
{
  unsigned int id;
  double timestamp;
  std::string content;
};

auto prepareDatabase()
{
  using namespace sqlite_orm;
  auto storage = make_storage
    ("h2o-stream.sqlite",
     make_table("events",
                make_column("id", &Event::id, autoincrement(), primary_key()),
                make_column("timestamp", &Event::timestamp),
                make_column("content", &Event::content)
                ));

  storage.sync_schema();
  auto eventCount = storage.count<Event>();
  if(eventCount < 1000000) {
    storage.transaction([&] () mutable {    //  mutable keyword allows make non-const function calls
        for(int n=0; n < 1000000; ++n) {
          Event e;
          e.id=0;
          e.timestamp=n;
          e.content = std::to_string(n);
          storage.insert(e);
        }
        return true;
      });
  }
  return storage;
}

using DBType=decltype(prepareDatabase());

struct State
{
  ~State()
  {
    delete iter;
    delete end;
    delete thing;
    delete db;
  }
  h2o_generator_t super;
  DBType* db;
  decltype(db->iterate<Event>())* thing;
  decltype(thing->begin()) *iter, *end;
  string batch;
};



void proceedSending(h2o_generator_t *self, h2o_req_t *req)
{
  State* state = (State*)self;
  cout << "proceedSending was called"<<endl;
  state->batch.clear();
  int count=0;
  for(; *state->iter != *state->end && count < 50000; ++(*state->iter), ++count) {
    state->batch.append(state->db->dump<Event>(**state->iter));
    state->batch.append(1, '\n');
  }
  
  h2o_iovec_t buf;
  buf.base=(char*)state->batch.c_str();
  buf.len = state->batch.size();
  h2o_send(req, &buf, 1, *state->iter == *state->end ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
}

void stopSending(h2o_generator_t *self, h2o_req_t *req)
{
  cout << "stopSending was called"<<endl;
}


int streamHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                 NULL, H2O_STRLIT("octet/stream"));
      
  // gather initial data from SQL query, store it in buf

  auto db = new DBType(prepareDatabase());
  auto thing = new decltype(db->iterate<Event>())(db->iterate<Event>());
  auto iter = new decltype(thing->begin())(thing->begin());
  auto end = new decltype(thing->end())(thing->end());

  State* state = (State*)h2o_mem_alloc_shared(&req->pool, sizeof(State), [](void *self)
                               {
                                 cout << "Dealloc" << endl;
                                 State* state = (State*) self;
                                 state->~State();
                               });
  h2o_generator_t generator{proceedSending, stopSending};
  new(state) State{generator, db, thing, iter, end}; 

  h2o_start_response(req, (h2o_generator_t*) state);
  
  proceedSending((h2o_generator_t*)state, req);
  return 0;
}

int main()
{
  auto db = prepareDatabase();
  signal(SIGPIPE, SIG_IGN); // every TCP application needs this

  // this only sets the hostname, using default ports (80, 443)
  // does not yet bind to sockets
  H2OWebserver h2s;
  h2s.addHandler("/events", [](auto handler, auto req) {
      pair<string, string> ret;
      ret.first="text/plain";
      auto db = prepareDatabase();
      for(auto &e : db.iterate<Event>()) {
        ret.second.append(db.dump(e));
        ret.second.append(1,'\n');
      }
      return ret;
    });
  h2s.addHandler("/events-streamed", streamHandler);
  auto actxt = h2s.addContext();
  h2s.addListener(ComboAddress("0.0.0.0:8001"), actxt);

  auto sslactx = h2s.addSSLContext("./fullchain.pem", "./privkey.pem");
  h2s.addListener(ComboAddress("0.0.0.0:4430"), sslactx);
  h2s.runLoop();  
}
