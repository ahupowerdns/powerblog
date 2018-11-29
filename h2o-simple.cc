#include "h2o-pp.hh"
#include <signal.h>
using namespace std;

int main(int argc, char** argv)
{
  signal(SIGPIPE, SIG_IGN); // every TCP application needs this

  // this only sets the hostname, using default ports (80, 443)
  // does not yet bind to sockets
  H2OWebserver h2s("live.powerdns.org"); 

  // serve the /files path from the local directory ./html/
  h2s.addDirectory("/files", "./html/");

  // the rest gets sent to this handler
  h2s.addHandler("/", [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";
      h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                     NULL, H2O_STRLIT("octet/stream"));
      h2o_send_inline(req, "Hello!", 6);
      return 0;
    });

  // SSL 
  auto sslactx = h2s.addSSLContext("./fullchain.pem", "./privkey.pem");
  h2s.addListener(ComboAddress("127.0.0.1", 443), sslactx);
  h2s.addListener(ComboAddress("::1", 443), sslactx);

  // plaintext 
  auto actx = h2s.addContext();
  h2s.addListener(ComboAddress("127.0.0.1:80"), actx);
  h2s.addListener(ComboAddress("[::1]:80"), actx);
  
 
  h2s.runLoop();
}
