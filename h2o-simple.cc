#include "h2o-pp.hh"
#include <vector>
#include <signal.h>
#include <nlohmann/json.hpp>
using namespace std;

static unsigned int hexToVal(char c)
{
  if(c>='0' && c<='9')
    return c-'0';
  else if(c>='a' && c<='f')
    return c-'a';
  else if(c>='A' && c<='F')
    return c-'A';
  else return 0;
}

auto urlDecode(std::string_view query)
{
  string ret;
  ret.reserve(query.size());
  for(auto iter = query.begin(); iter != query.end(); ++iter) {
    if(*iter=='%') {
      char c=0;
      ++iter;
      if(iter!=query.end()) {
        c=0x10*hexToVal(*iter);
        ++iter;
        if(iter!=query.end()) {
          c+=hexToVal(*iter);
        }
      }
      ret.append(1,c);
    }
    else ret.append(1, *iter);
  }
  return ret;
}

auto urlParameterDecode(std::string_view query)
{
  vector<pair<string,string>> ret;
  std::string_view::size_type npos=0;
  int count=100;
  for(;;) {
    if(!--count)
      break;
    cout << "Rest: "<<query << endl;
    npos = query.find('&');
    if(npos == string::npos) {
      cout<<" END!"<<endl;
      npos = query.size();
    }
    
    std::string_view ppair(&query[0], npos);
    cout<<" ppair: "<<ppair<<endl;
    auto epos = ppair.find('=');
    pair<string,string> cur;
    if(epos != string::npos) {
      ret.push_back({urlDecode(ppair.substr(0, epos)), urlDecode(ppair.substr(epos+1))});
    }
    else {
      ret.push_back({urlDecode(ppair), string()});
    }
    if(npos == query.size())
      break;
    query.remove_prefix(npos+1);
  } 
  
  return ret;
}

int main(int argc, char** argv)
{
  signal(SIGPIPE, SIG_IGN); // every TCP application needs this

  // this only sets the hostname, using default ports (80, 443)
  // does not yet bind to sockets
  H2OWebserver h2s("live.powerdns.org"); 

  // serve the /files path from the local directory ./html/
  h2s.addDirectory("/files", "./html/");

  h2s.addHandler("/dateHandler", [](auto handler, auto req) -> std::pair<std::string, std::string>
                 {
                   return {"text/plain", "The time\r\n"};
                 });

  h2s.addHandler("/hello", [](auto handler, auto req) -> std::pair<std::string, std::string>
                 {
                   return {"text/html", "<html><body>Hello, world</body></html>"};
                 });

  h2s.addHandler("/date", [](auto handler, auto req) 
                 {
                   nlohmann::json ret;
                   ret["month"]="December";
                   ret["day"]=1;
                   ret["year"]=2018;
                   return ret;
                 });

  
  // the rest gets sent to this handler
  h2s.addHandler("/", [](auto handler, auto req) {
      req->res.status = 200;
      req->res.reason = "OK";

      auto authority = convert(req->input.authority), method=convert(req->input.method), path=convert(req->input.path);
      cout<<"authority: "<<authority<<endl;
      cout<<"method: "<<method<<endl;
      cout<<"path: "<<path<<", "<<req->input.query_at<<endl;
      if(req->input.query_at != SIZE_MAX) {
        std::string_view query = path;
        query.remove_prefix(req->input.query_at + 1);
        cout<<"Query: "<<query<<endl;
        auto dec = urlParameterDecode(query);
        for(const auto& p : dec) {
          cout << "'"<<p.first<<"' = '"<<p.second<<"'"<<endl;
        }
      }
      
      h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, 
                     NULL, H2O_STRLIT("octet/stream"));
      h2o_send_inline(req, "Hello!", 6);
      return 0;
    });


  
  // SSL 
  auto sslactx = h2s.addSSLContext("./fullchain.pem", "./privkey.pem");
  h2s.addListener(ComboAddress("127.0.0.1", 4430), sslactx);
  h2s.addListener(ComboAddress("::1", 4430), sslactx);

  // plaintext 
  auto actx = h2s.addContext();
  h2s.addListener(ComboAddress("127.0.0.1:8000"), actx);
  h2s.addListener(ComboAddress("[::1]:8000"), actx);
  
 
  h2s.runLoop();
}
