#include "uri.hpp"

#include <glog/logging.h>

#include <regex>

// From: <https://tools.ietf.org/html/rfc3986#appendix-B>

// Appendix B.  Parsing a URI Reference with a Regular Expression
//      12            3  4          5       6  7        8 9
//     ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
auto constexpr uri_re_str
    = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?";

auto const uri_re{std::regex{uri_re_str}};

bool uri_parse_re(std::string_view uri, uri::components& parts)
{
  std::cmatch what;

  if (!std::regex_match(begin(uri), end(uri), what, uri_re))
    return false;

  if (what.size() > 9)
    parts.fragment
        = std::string_view(cbegin(uri) + what.position(9), what.length(9));
  if (what.size() > 7)
    parts.query
        = std::string_view(cbegin(uri) + what.position(7), what.length(7));
  if (what.size() > 5)
    parts.path
        = std::string_view(cbegin(uri) + what.position(5), what.length(5));
  if (what.size() > 4)
    parts.authority
        = std::string_view(cbegin(uri) + what.position(4), what.length(4));
  if (what.size() > 2)
    parts.scheme
        = std::string_view(cbegin(uri) + what.position(2), what.length(2));

  return true;
}

int main(int argc, char* argv[])
{
  using std::string_view;

  // First, verify that uri_re works like the RFC says it should.

  // From RFC 3986, page 51

  auto u = "http://www.ics.uci.edu/pub/ietf/uri/#Related";

  std::cmatch m;
  CHECK(std::regex_match(u, m, uri_re));

  CHECK_EQ(m.size(), 10);
  CHECK_EQ(string_view(u + m.position(0), m.length(0)), u);
  CHECK_EQ(string_view(u + m.position(1), m.length(1)), "http:");
  CHECK_EQ(string_view(u + m.position(2), m.length(2)), "http");
  CHECK_EQ(string_view(u + m.position(3), m.length(3)), "//www.ics.uci.edu");
  CHECK_EQ(string_view(u + m.position(4), m.length(4)), "www.ics.uci.edu");
  CHECK_EQ(string_view(u + m.position(5), m.length(5)), "/pub/ietf/uri/");
  CHECK_EQ(string_view(u + m.position(6), m.length(6)), "");
  CHECK_EQ(string_view(u + m.position(7), m.length(7)), "");
  CHECK_EQ(string_view(u + m.position(8), m.length(8)), "#Related");
  CHECK_EQ(string_view(u + m.position(9), m.length(9)), "Related");

  // Next, compare our parser's results vs. the regular expression for
  // a bunch of URIs.

  char const* good_uris[]{
      "http://www.ics.uci.edu/pub/ietf/uri/#Related",
      "http://-.~_!$&'()*+,;=:%40:80%2f::::::@example.com",
      "ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm",
      "http://www.ics.uci.edu/pub/ietf/uri/#Related",
      "https://tools.ietf.org/html/rfc3986#appendix-B",
      "http://example.com",
      "http://example.com/",
      "http://example.com:/",
      "http://example.com:80/",
      "http://example.com:80",
      "http://example.com:",
      "foo://example.com:8042/over/there?name=ferret#nose",
      "foo://dude@example.com:8042/over/there?name=ferret#nose",
      "urn:example:animal:ferret:nose",
      "http://foo.com/blah_blah",
      "http://foo.com/blah_blah/",
      "http://foo.com/blah_blah_(wikipedia)",
      "http://foo.com/blah_blah_(wikipedia)_(again)",
      "http://www.example.com/wpstyle/?p=364",
      "https://www.example.com/foo/?bar=baz&inga=42&quux",
      "http://✪df.ws/123",
      "http://userid:password@example.com:8080",
      "http://userid:password@example.com:8080/",
      "http://userid@example.com",
      "http://userid@example.com/",
      "http://userid@example.com:8080",
      "http://userid@example.com:8080/",
      "http://userid:password@example.com",
      "http://userid:password@example.com/",
      "http://142.42.1.1/",
      "http://142.42.1.1:8080/",
      "http://➡.ws/䨹",
      "http://⌘.ws",
      "http://⌘.ws/",
      "http://foo.com/blah_(wikipedia)#cite-1",
      "http://foo.com/blah_(wikipedia)_blah#cite-1",
      "http://foo.com/unicode_(✪)_in_parens",
      "http://foo.com/(something)?after=parens",
      "http://☺.damowmow.com/",
      "http://code.google.com/events/#&product=browser",
      "http://j.mp",
      "ftp://foo.bar/baz",
      "http://foo.bar/?q=Test%20URL-encoded%20stuff",
      "http://مثال.إختبار",
      "http://例子.测试",
      "http://उदाहरण.परीक्षा",
      "http://-.~_!$&'()*+,;=:%40:80%2f::::::@example.com",
      "http://1337.net",
      "http://a.b-c.de",
      "http://223.255.255.254",
      "ftp://ftp.is.co.za/rfc/rfc1808.txt",
      "http://www.ietf.org/rfc/rfc2396.txt",
      "ldap://[2001:db8::7]/c=GB?objectClass?one",
      "mailto:John.Doe@example.com",
      "news:comp.infosystems.www.servers.unix",
      "tel:+1-816-555-1212",
      "telnet://192.0.2.16:80/",
      "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
      "https://🍔.digilicious.com/",
      "https://xn--ui8h.digilicious.com/",
      "https://xn--ui8h%2Edigilicious%2Ecom/",
      "https://xn%2D%2Dui8h%2Edigilicious%2Ecom/",
  };

  for (auto uri : good_uris) {
    uri::components parts;
    CHECK(uri_parse_re(uri, parts));

    uri::uri u{uri};

    CHECK_EQ(parts.scheme, u.scheme());

    CHECK_EQ(parts.authority, u.authority());

    CHECK_EQ(parts.path, u.path());
    CHECK_EQ(parts.query, u.query());
    CHECK_EQ(parts.fragment, u.fragment());

    // Make sure we can put it back together as a string and get the
    // original URI.

    CHECK_EQ(to_string(u), uri);
  }

  // Verify a bunch of bad URIs all throw exceptions.

  char const* bad_uris[]{
      "http://",
      "http://.",
      "http://..",
      "http://../",
      "http://?",
      "http://?\?",
      "http://?\?/",
      "http://#",
      "http://##",
      "http://##/",
      "http://foo.bar?q=Spaces should be encoded",
      "//",
      "//a",
      "///a",
      "///",
      "http:///a",
      "foo.com",
      "http:// shouldfail.com",
      ":// should fail",
      "http://foo.bar/foo(bar)baz quux",
      "http://-error-.invalid/",
      "http://-a.b.co",
      "http://a.b-.co",
      "http://1.1.1.1.1",
      "http://.www.foo.bar/",
      "http://.www.foo.bar./",
  };

  // I have to confess, I don't know what's wrong with these:

  //  "ftps://foo.bar/",
  //  "http://a.b--c.de/",
  //  "rdar://1234",
  //  "h://test",
  //  "http://0.0.0.0",
  //  "http://10.1.1.0",
  //  "http://10.1.1.255",
  //  "http://224.1.1.1",
  //  "http://123.123.123",
  //  "http://3628126748",
  //  "http://www.foo.bar./",
  //  "http://10.1.1.1",
  //  "http://10.1.1.254",

  auto failures = 0;

  for (auto uri : bad_uris) {
    try {
      uri::uri u{uri};
      LOG(ERROR) << "should not parse \"" << uri << "\" as \"" << u << "\"\n";
      ++failures;
    }
    catch (uri::syntax_error const& e) {
      // all good
    }
    catch (std::exception const& e) {
      LOG(FATAL) << "unexpected exception " << e.what() << '\n';
    }
  }

  // Parse all the command line args as URIs.

  for (auto i = 1; i < argc; ++i) {
    uri::uri u{argv[i]};

    std::cout << "scheme()     == " << u.scheme() << '\n';
    std::cout << "authority()  == " << u.authority() << '\n';
    std::cout << "userinfo()   == " << u.userinfo() << '\n';
    std::cout << "host()       == " << u.host() << '\n';
    std::cout << "port()       == " << u.port() << '\n';
    std::cout << "path()       == " << u.path() << '\n';
    std::cout << "query()      == " << u.query() << '\n';
    std::cout << "fragment()   == " << u.fragment() << '\n';

    uri::components parts;
    CHECK(uri_parse_re(argv[i], parts));

    std::cout << "re scheme    == " << parts.scheme << '\n';
    std::cout << "re authority == " << parts.authority << '\n';
    std::cout << "re query     == " << parts.query << '\n';
    std::cout << "re fragment  == " << parts.fragment << '\n';

    std::cout << "normal form  == " << uri::normalize(u.parts()) << '\n';
  }

  return failures;
}
