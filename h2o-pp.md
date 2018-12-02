# h2o-pp
`h2o-pp` is a "non-wrapper" of the excellent `libh2o` library that also
powers the `h2o` webserver.

The goal of `h2o-pp` is to make it very easy to host (RESTful) APIs and
files from modern C++, powered by a full-featured, industrial strength,
high-performance HTTP library.

It is called a "non-wrapper" since `h2o-pp` in no way abstracts `libh2o`.
All the power of `libh2o` is available directly and you can freely mix
native `libh2o` functions with the convenience functions that `h2o-pp`
offers.

This is good since `libh2o` offers 'the kitchen sink' in terms of HTTP,
HTTP/2 and TLS features. Not all of these are needed all the time, so to
keep the `h2o-pp` interface simple, we do not bother our users with all
features all the time. However, the full power of `libh2o` is easily
available since the `h2o` handles are exposed.

More about `libh2o` can be found in the [documentation we
contributed](https://powerdns.org/libh2o).

Meanwhile, all methods and functions of `h2o-pp` are described in the
[h2o-pp.hh](https://github.com/ahupowerdns/powerblog/blob/master/h2o-pp.hh)
header file.

## Hello world
This small sample below delivers an HTTP/2 & TLS-enabled webserver, serving
files, a plain text string, a tiny HTML page and a JSON object:

```
  signal(SIGPIPE, SIG_IGN); // every TCP application needs this

  // this only sets the hostname, using default ports (80, 443)
  // does not yet bind to sockets
  H2OWebserver h2s("live.powerdns.org"); 

  // serve the /files path from the local directory ./html/
  h2s.addDirectory("/files", "./html/");

  h2s.addHandler("/hello", [](auto handler, auto req) 
                 {
                   return pair<string,string>("text/plain", "Hello, world");
                 });

  // slightly different syntax, achieving the same thing
  h2s.addHandler("/hello.html", [](auto handler, auto req) -> pair<string, string>
                 {
                   return {"text/html", "<html><body>Hello, world</body></html>"};
                 });

  // serve up JSON
  h2s.addHandler("/date", [](auto handler, auto req) 
                 {
                   nlohmann::json ret;
                   ret["month"]="December";
                   ret["day"]=1;
                   ret["year"]=2018;
                   return ret;
                 });

  // SSL 
  auto sslactx = h2s.addSSLContext("./fullchain.pem", "./privkey.pem");
  h2s.addListener(ComboAddress("127.0.0.1", 443), sslactx);
  h2s.addListener(ComboAddress("::1", 443), sslactx);

  // Plaintext
  auto actx = h2s.addContext();
  h2s.addListener(ComboAddress("127.0.0.1:80"), actx);
  h2s.addListener(ComboAddress("[::1]:80"), actx);
 
  h2s.runLoop();
```

Many, many projects should be covered completely by the functionality
covered in this 'hello world' sample. But this is not everything that
`h2o-pp` has to offer. 

More details are in
[h2o-simple.cc](https://github.com/ahupowerdns/powerblog/blob/master/h2o-real.cc).

## Separate behaviour for different hosts & protocols
To make a plaintext server that redirects to HTTPS, and serves some content
there:

```
  H2OWebserver h2s("live.powerdns.org", 443); 
  auto plaintext = h2s.addHost("www.powerdns.org", 80);

  // handler on the plaintext 'authority'
  h2s.addHandler("/", [](h2o_handler_t* handler, h2o_req_t* req)
                 {
                   std::string_view path=convert(req->path);
                   h2o_send_redirect(req, 301, "Moved Permanently", H2O_STRLIT("https://live.powerdns.org/"));
                   return 0;
                 }, plaintext); 

  // handler on the default port 443
  h2s.addDirectory("/", "./html/");
```

This is a good example of using an `libh2o` function from `h2o-pp`, which we
use to create a redirect. Note also how we call `convert` to convert a
native `h2o_iovec_t` to a `std::string_view`, which makes no copy but
provides a `std::string` compatible view of the data.

More details are in
[h2o-real.cc](https://github.com/ahupowerdns/powerblog/blob/master/h2o-real.cc).

# Accessing URL parameters & headers
`libh2o` really is an HTTP library and not so much a URL parsing library.
This is one area where `h2o-pp` does extra lifting.

First, various request headers:

```
  h2s.addHandler("/", [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";

      auto authority = convert(req->input.authority), method=convert(req->input.method), path=convert(req->input.path);
      cout<<"authority: "<<authority<<endl;
      cout<<"method: "<<method<<endl;
      cout<<"path: "<<path<<", "<<req->input.query_at<<endl;
```

This accesses the authority ('host name'), the method (GET/POST) and the
path. For the path, it also tells us where the first '?' is, where the query
starts.

To access the URL parameters, do:
```
      if(req->input.query_at != SIZE_MAX) {
        std::string_view query = path;
        query.remove_prefix(req->input.query_at + 1);

        auto dec = urlParameterDecode(query);
        for(const auto& p : dec) {
          cout << "'"<<p.first<<"' = '"<<p.second<<"'"<<endl;
        }
      }
```

This syntax is provisional and will likely be replaced. 

To access headers from a handler, try:

```
  for (unsigned int i = 0; i != req->headers.size; ++i) {
    std::string_view hdr = convert(req->headers.entries[i].name); 

    if(hdr=="cookie") {
      auto val = convert(req->headers.entries[i].value);
      // cookies are now in 'val'
    }
  }

```

# Advanced

## Streaming output
Queries that generate large amounts of output are typically buffered in
memory in less powerful HTTP libraries. `libh2o` however offers us the
possibility to *stream* output to clients.

This does require some coordination & understanding of `libh2o`,
specifically how `generators` work. It is suggested to first read the
[generator](https://powerdns.org/libh2o/#generators) part of the `libh2o`
documentation before proceeding.

First, the non-streaming variant:

```
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
```
This retrieves events from a SQLite database, by default provisioned with 1
million rows. This takes 2 seconds to retrieve & build the gigantic 55MB
`ret` response variable. This is then sent in one go to the client.

Now, the streaming variant. First we need a place to store where we are in
the SQL query:

```
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
```

This syntax is rather convoluted since the `sqlite_orm` library does not
make it easy to store its state.

```
int streamHandler(h2o_handler_t* handler, h2o_req_t* req)
{
  req->res.status = 200;
  req->res.reason = "OK";
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                 NULL, H2O_STRLIT("octet/stream"));
```

This is the initial part where we set the response status & the Content-Type
response header.

Here we setup the database connection, which is rather involved since
(again) the otherwise wonderful `sqlite_orm` library does not make it easy
to move itself around:
      
```
  // gather initial data from SQL query, store it in buf

  auto db = new DBType(prepareDatabase());
  auto search = new decltype(db->iterate<Event>())(db->iterate<Event>());
  auto iter = new decltype(search->begin())(search->begin());
  auto end = new decltype(search->end())(search->end());
```

Then, we need to store the state of the search:

```
  State* state = (State*)h2o_mem_alloc_shared(&req->pool, sizeof(State), [](void *self)
                               {
                                 State* state = (State*) self;
                                 state->~State();
                               });
  h2o_generator_t generator{proceedSending, stopSending};
  new(state) State{generator, db, search, iter, end}; 
```

This uses the `libh2o` memory allocator to create storage for our `State`
and attaches it to our request. It also defines a `dispose` callback that
gets called once the HTTP request has been finished. We need to call the
destructor ourself since the C `free` function won't do that for us later.

Next up, we register our `state` as the generator, and call the
`proceedSending` callback to send out the first batch of events/rows:

```
  h2o_start_response(req, (h2o_generator_t*) state);
  
  proceedSending((h2o_generator_t*)state, req);
  return 0;
}
```

And finally, here is `proceedSending`:

```
void proceedSending(h2o_generator_t *self, h2o_req_t *req)
{
  State* state = (State*)self;
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
```

This stores at most 50000 events & then sends them off to the client. If we
found that we are at the end of the results, we set the
`H2O_SEND_STATE_FINAL` flag, which tells `libh2o` we are done.

More details are in
[h2o-stream.cc](https://github.com/ahupowerdns/powerblog/blob/master/h2o-stream.cc).
