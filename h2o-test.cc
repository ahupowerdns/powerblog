#include "h2o-pp.hh"

int main(int argc, char** argv)
{
  H2OWebserver h2s("live.powerdns.org");

  auto host = h2s.addHost("www.live.powerdns.org");
  
  h2s.addHandler("/een", [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";
      h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                     NULL, H2O_STRLIT("octet/stream"));
      h2o_send_inline(req, "Hallo!", 6);
      return 0;
    }, host);

  h2s.addHandler("/", [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";
      h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                     NULL, H2O_STRLIT("octet/stream"));
      h2o_send_inline(req, "HALLO!", 6);
      return 0;
    });

 
  auto sslactx = h2s.getSSLContext("./fullchain.pem", "./privkey.pem", "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK");

  ComboAddress local("127.0.0.1", 4430);
  h2s.addListener(local, sslactx);
  h2s.addListener(ComboAddress("::1", 4430), sslactx);

  auto actx = h2s.getContext();
  h2s.addListener(ComboAddress("127.0.0.1:8000"), actx);
  h2s.addListener(ComboAddress("[::1]:8000"), actx);
  
 
  h2s.runLoop();
}
