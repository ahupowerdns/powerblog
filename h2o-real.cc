#include "h2o-pp.hh"
#include <signal.h>
using namespace std;

int main(int argc, char** argv)
{
  signal(SIGPIPE, SIG_IGN); // every TCP application needs this

  // this only sets the hostname, using default ports (80, 443)
  // does not yet bind to sockets
  H2OWebserver h2s("live.powerdns.org"); 

  // creates two new hosts, one on port 4430, one on port 8000
  auto hostssl = h2s.addHost("www.live.powerdns.org", 4430);
  auto host = h2s.addHost("www.live.powerdns.org", 8000);

  // defines a handler that can be shared
  auto lower = [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";
      h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                     NULL, H2O_STRLIT("octet/stream"));
      h2o_send_inline(req, "Hallo!", 6);
      return 0;
  };

  // we need to add this handler to both www.live.powerdns.org ports
  h2s.addHandler("/een", lower, hostssl);
  h2s.addHandler("/een", lower, host);

  // we serve files from all hostnames
  h2s.addDirectory("/files", "html/");
  h2s.addDirectory("/files", "html/", host);
  h2s.addDirectory("/files", "html/", hostssl);

  // this is the default handler that is ONLY defined on the default
  // (first) host
  h2s.addHandler("/", [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";
      h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                     NULL, H2O_STRLIT("octet/stream"));
      h2o_send_inline(req, "HALLO!", 6);
      return 0;
    });

 
  auto sslactx = h2s.addSSLContext("./fullchain.pem", "./privkey.pem");

  // make SSL listen on IPv4 and IPv6
  h2s.addListener(ComboAddress("127.0.0.1", 443), sslactx);
  h2s.addListener(ComboAddress("::1", 443), sslactx);
  h2s.addListener(ComboAddress("::1", 4430), sslactx);

  // and plaintext
  auto actx = h2s.addContext();
  h2s.addListener(ComboAddress("127.0.0.1:8000"), actx);
  h2s.addListener(ComboAddress("127.0.0.1:80"), actx);
 
  h2s.runLoop();
}
