#include "uri.hpp"

#include <glog/logging.h>

#include <gflags/gflags.h>
namespace gflags {
// in case we didn't have one
}

bool operator==(uri::components const& lhs, uri::components const& rhs)
{
  return (lhs.scheme == rhs.scheme) && (lhs.authority == rhs.authority)
         && (lhs.userinfo == rhs.userinfo) && (lhs.host == rhs.host)
         && (lhs.port == rhs.port) && (lhs.path == rhs.path)
         && (lhs.query == rhs.query) && (lhs.fragment == rhs.fragment);
}

bool operator!=(uri::components const& lhs, uri::components const& rhs)
{
  return !(lhs == rhs);
}

int test_good()
{
  struct test_case {
    char const* uri;
    uri::components parts;
  };

  // clang-format off
  test_case tests[] = {
  {"foo://dude@example.com:8042/over/there?name=ferret#nose",
  {"foo", "dude@example.com:8042", "dude", "example.com", "8042", "/over/there", "name=ferret", "nose", }, },

  {"foo://example.com:8042/over/there?name=ferret#nose",
  {"foo", "example.com:8042", {}, "example.com", "8042", "/over/there", "name=ferret", "nose", }, },

  {"ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm",
  {"ftp", "cnn.example.com&story=breaking_news@10.0.0.1", "cnn.example.com&story=breaking_news", "10.0.0.1", {}, "/top_story.htm", {}, {}, }, },

  {"ftp://foo.bar/baz",
  {"ftp", "foo.bar", {}, "foo.bar", {}, "/baz", {}, {}, }, },

  {"ftp://ftp.is.co.za/rfc/rfc1808.txt",
  {"ftp", "ftp.is.co.za", {}, "ftp.is.co.za", {}, "/rfc/rfc1808.txt", {}, {}, }, },

  {"http://-.~_!$&'()*+,;=:%40:80%2f::::::@example.com",
  {"http", "-.~_!$&'()*+,;=:%40:80%2f::::::@example.com", "-.~_!$&'()*+,;=:%40:80%2f::::::", "example.com", {}, "", {}, {}, }, },

  {"http://1337.net",
  {"http", "1337.net", {}, "1337.net", {}, "", {}, {}, }, },

  {"http://142.42.1.1/",
  {"http", "142.42.1.1", {}, "142.42.1.1", {}, "/", {}, {}, }, },

  {"http://142.42.1.1:8080/",
  {"http", "142.42.1.1:8080", {}, "142.42.1.1", "8080", "/", {}, {}, }, },

  {"http://223.255.255.254",
  {"http", "223.255.255.254", {}, "223.255.255.254", {}, "", {}, {}, }, },

  {"http://a.b-c.de",
  {"http", "a.b-c.de", {}, "a.b-c.de", {}, "", {}, {}, }, },

  {"http://code.google.com/events/#&product=browser",
  {"http", "code.google.com", {}, "code.google.com", {}, "/events/", {}, "&product=browser", }, },

  {"http://example.com",
  {"http", "example.com", {}, "example.com", {}, "", {}, {}, }, },

  {"http://example.com/",
  {"http", "example.com", {}, "example.com", {}, "/", {}, {}, }, },

  {"http://example.com:",
  {"http", "example.com:", {}, "example.com", "", "", {}, {}, }, },

  {"http://example.com:/",
  {"http", "example.com:", {}, "example.com", "", "/", {}, {}, }, },

  {"http://example.com:80",
  {"http", "example.com:80", {}, "example.com", "80", "", {}, {}, }, },

  {"http://example.com:80/",
  {"http", "example.com:80", {}, "example.com", "80", "/", {}, {}, }, },

  {"http://foo.bar/?q=Test%20URL-encoded%20stuff",
  {"http", "foo.bar", {}, "foo.bar", {}, "/", "q=Test%20URL-encoded%20stuff", {}, }, },

  {"http://foo.com/(something)?after=parens",
  {"http", "foo.com", {}, "foo.com", {}, "/(something)", "after=parens", {}, }, },

  {"http://foo.com/blah_(wikipedia)#cite-1",
  {"http", "foo.com", {}, "foo.com", {}, "/blah_(wikipedia)", {}, "cite-1", }, },

  {"http://foo.com/blah_(wikipedia)_blah#cite-1",
  {"http", "foo.com", {}, "foo.com", {}, "/blah_(wikipedia)_blah", {}, "cite-1", }, },

  {"http://foo.com/blah_blah",
  {"http", "foo.com", {}, "foo.com", {}, "/blah_blah", {}, {}, }, },

  {"http://foo.com/blah_blah/",
  {"http", "foo.com", {}, "foo.com", {}, "/blah_blah/", {}, {}, }, },

  {"http://foo.com/blah_blah_(wikipedia)",
  {"http", "foo.com", {}, "foo.com", {}, "/blah_blah_(wikipedia)", {}, {}, }, },

  {"http://foo.com/blah_blah_(wikipedia)_(again)",
  {"http", "foo.com", {}, "foo.com", {}, "/blah_blah_(wikipedia)_(again)", {}, {}, }, },

  {"http://foo.com/unicode_(✪)_in_parens",
  {"http", "foo.com", {}, "foo.com", {}, "/unicode_(✪)_in_parens", {}, {}, }, },

  {"http://j.mp",
  {"http", "j.mp", {}, "j.mp", {}, "", {}, {}, }, },

  {"http://userid:password@example.com",
  {"http", "userid:password@example.com", "userid:password", "example.com", {}, "", {}, {}, }, },

  {"http://userid:password@example.com/",
  {"http", "userid:password@example.com", "userid:password", "example.com", {}, "/", {}, {}, }, },

  {"http://userid:password@example.com:8080",
  {"http", "userid:password@example.com:8080", "userid:password", "example.com", "8080", "", {}, {}, }, },

  {"http://userid:password@example.com:8080/",
  {"http", "userid:password@example.com:8080", "userid:password", "example.com", "8080", "/", {}, {}, }, },

  {"http://userid@example.com",
  {"http", "userid@example.com", "userid", "example.com", {}, "", {}, {}, }, },

  {"http://userid@example.com/",
  {"http", "userid@example.com", "userid", "example.com", {}, "/", {}, {}, }, },

  {"http://userid@example.com:8080",
  {"http", "userid@example.com:8080", "userid", "example.com", "8080", "", {}, {}, }, },

  {"http://userid@example.com:8080/",
  {"http", "userid@example.com:8080", "userid", "example.com", "8080", "/", {}, {}, }, },

  {"http://www.example.com/wpstyle/?p=364",
  {"http", "www.example.com", {}, "www.example.com", {}, "/wpstyle/", "p=364", {}, }, },

  {"http://www.ics.uci.edu/pub/ietf/uri/#Related",
  {"http", "www.ics.uci.edu", {}, "www.ics.uci.edu", {}, "/pub/ietf/uri/", {}, "Related", }, },

  {"http://www.ietf.org/rfc/rfc2396.txt",
  {"http", "www.ietf.org", {}, "www.ietf.org", {}, "/rfc/rfc2396.txt", {}, {}, }, },

  {"http://مثال.إختبار",
  {"http", "مثال.إختبار", {}, "مثال.إختبار", {}, "", {}, {}, }, },

  {"http://उदाहरण.परीक्षा",
  {"http", "उदाहरण.परीक्षा", {}, "उदाहरण.परीक्षा", {}, "", {}, {}, }, },

  {"http://⌘.ws",
  {"http", "⌘.ws", {}, "⌘.ws", {}, "", {}, {}, }, },

  {"http://⌘.ws/",
  {"http", "⌘.ws", {}, "⌘.ws", {}, "/", {}, {}, }, },

  {"http://☺.damowmow.com/",
  {"http", "☺.damowmow.com", {}, "☺.damowmow.com", {}, "/", {}, {}, }, },

  {"http://✪df.ws/123",
  {"http", "✪df.ws", {}, "✪df.ws", {}, "/123", {}, {}, }, },

  {"http://➡.ws/䨹",
  {"http", "➡.ws", {}, "➡.ws", {}, "/䨹", {}, {}, }, },

  {"http://例子.测试",
  {"http", "例子.测试", {}, "例子.测试", {}, "", {}, {}, }, },

  {"https://tools.ietf.org/html/rfc3986#appendix-B",
  {"https", "tools.ietf.org", {}, "tools.ietf.org", {}, "/html/rfc3986", {}, "appendix-B", }, },

  {"https://www.example.com/foo/?bar=baz&inga=42&quux",
  {"https", "www.example.com", {}, "www.example.com", {}, "/foo/", "bar=baz&inga=42&quux", {}, }, },

  {"https://xn%2D%2Dui8h%2Edigilicious%2Ecom/",
  {"https", "xn%2D%2Dui8h%2Edigilicious%2Ecom", {}, "xn%2D%2Dui8h%2Edigilicious%2Ecom", {}, "/", {}, {}, }, },

  {"https://xn--ui8h%2Edigilicious%2Ecom/",
  {"https", "xn--ui8h%2Edigilicious%2Ecom", {}, "xn--ui8h%2Edigilicious%2Ecom", {}, "/", {}, {}, }, },

  {"https://xn--ui8h.digilicious.com/",
  {"https", "xn--ui8h.digilicious.com", {}, "xn--ui8h.digilicious.com", {}, "/", {}, {}, }, },

  {"https://🍔.digilicious.com/",
  {"https", "🍔.digilicious.com", {}, "🍔.digilicious.com", {}, "/", {}, {}, }, },

  {"ldap://[2001:db8::7]/c=GB?objectClass?one",
  {"ldap", "[2001:db8::7]", {}, "[2001:db8::7]", {}, "/c=GB", "objectClass?one", {}, }, },

  {"mailto:John.Doe@example.com",
  {"mailto", {}, {}, {}, {}, "John.Doe@example.com", {}, {}, }, },

  { "mailto:%22not%40me%22@example.org",
    {
    /*  scheme*/ "mailto",
    /*    auth*/ {},
    /*userinfo*/ {},
    /*    host*/ {},
    /*    port*/ {},
    /*    path*/ "%22not%40me%22@example.org",
    /*   query*/ {},
    /*fragment*/ {},
    },
  },

  {"news:comp.infosystems.www.servers.unix",
  {"news", {}, {}, {}, {}, "comp.infosystems.www.servers.unix", {}, {}, }, },

  {"tel:+1-816-555-1212",
  {"tel", {}, {}, {}, {}, "+1-816-555-1212", {}, {}, }, },

  {"telnet://192.0.2.16:80/",
  {"telnet", "192.0.2.16:80", {}, "192.0.2.16", "80", "/", {}, {}, }, },

  {"urn:example:animal:ferret:nose",
  {"urn", {}, {}, {}, {}, "example:animal:ferret:nose", {}, {}, }, },

  {"urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
  {"urn", {}, {}, {}, {}, "oasis:names:specification:docbook:dtd:xml:4.1.2", {}, {}, }, },
  };
  // clang-format on

  auto failures = 0;

  for (auto&& test : tests) {
    uri::generic u{test.uri};
    if (test.parts != u.parts()) {
      std::cerr << test.uri << " failed to check\n";

      std::cout << "URL:\n";
      if (u.scheme())
        std::cout << "scheme()     == " << *u.scheme() << '\n';
      if (u.authority())
        std::cout << "authority()  == " << *u.authority() << '\n';
      if (u.userinfo())
        std::cout << "userinfo()   == " << *u.userinfo() << '\n';
      if (u.host())
        std::cout << "host()       == " << *u.host() << '\n';
      if (u.port())
        std::cout << "port()       == " << *u.port() << '\n';
      if (u.path())
        std::cout << "path()       == " << *u.path() << '\n';
      if (u.query())
        std::cout << "query()      == " << *u.query() << '\n';
      if (u.fragment())
        std::cout << "fragment()   == " << *u.fragment() << '\n';

      std::cout << "\ntest:\n";

      if (test.parts.scheme)
        std::cout << "scheme     == " << *test.parts.scheme << '\n';
      if (test.parts.authority)
        std::cout << "authority  == " << *test.parts.authority << '\n';
      if (test.parts.userinfo)
        std::cout << "userinfo   == " << *test.parts.userinfo << '\n';
      if (test.parts.host)
        std::cout << "host       == " << *test.parts.host << '\n';
      if (test.parts.port)
        std::cout << "port       == " << *test.parts.port << '\n';
      if (test.parts.path)
        std::cout << "path       == " << *test.parts.path << '\n';
      if (test.parts.query)
        std::cout << "query      == " << *test.parts.query << '\n';
      if (test.parts.fragment)
        std::cout << "fragment   == " << *test.parts.fragment << '\n';

      std::cout << "\n";

      ++failures;
    }
  }

  return failures;
}

int test_bad()
{
  // Verify a bunch of bad URIs all throw exceptions.
  auto failures = 0;

  constexpr char const* bad_uris[]{
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
  //  "http://10.1.1.1",
  //  "http://10.1.1.254",
  //  "http://www.foo.bar./",

  for (auto uri : bad_uris) {
    try {
      uri::generic u{uri};
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

  return failures;
}

int test_resolution()
{
  struct test_case {
    char const* ref;
    char const* resolved;
  };

  // clang-format off
  constexpr test_case tests[] = {

      // 5.4.1.  Normal Examples

      {"g:h",     "g:h"},
      {"g",       "http://a/b/c/g"},
      {"./g",     "http://a/b/c/g"},
      {"g/",      "http://a/b/c/g/"},
      {"/g",      "http://a/g"},
      {"//g",     "http://g"},
      {"?y",      "http://a/b/c/d;p?y"},
      {"g?y",     "http://a/b/c/g?y"},
      {"#s",      "http://a/b/c/d;p?q#s"},
      {"g#s",     "http://a/b/c/g#s"},
      {"g?y#s",   "http://a/b/c/g?y#s"},
      {";x",      "http://a/b/c/;x"},
      {"g;x",     "http://a/b/c/g;x"},
      {"g;x?y#s", "http://a/b/c/g;x?y#s"},
      {"",        "http://a/b/c/d;p?q"},
      {".",       "http://a/b/c/"},
      {"./",      "http://a/b/c/"},
      {"..",      "http://a/b/"},
      {"../",     "http://a/b/"},
      {"../g",    "http://a/b/g"},
      {"../..",   "http://a/"},
      {"../../",  "http://a/"},
      {"../../g", "http://a/g"},

      // 5.4.2.  Abnormal Examples

      {"../../../g",    "http://a/g"},
      {"../../../../g", "http://a/g"},

      {"/./g",          "http://a/g"},
      {"/../g",         "http://a/g"},
      {"g.",            "http://a/b/c/g."},
      {".g",            "http://a/b/c/.g"},
      {"g..",           "http://a/b/c/g.."},
      {"..g",           "http://a/b/c/..g"},

      {"./../g",        "http://a/b/g"},
      {"./g/.",         "http://a/b/c/g/"},
      {"g/./h",         "http://a/b/c/g/h"},
      {"g/../h",        "http://a/b/c/h"},
      {"g;x=1/./y",     "http://a/b/c/g;x=1/y"},
      {"g;x=1/../y",    "http://a/b/c/y"},

      {"g?y/./x",       "http://a/b/c/g?y/./x"},
      {"g?y/../x",      "http://a/b/c/g?y/../x"},
      {"g#s/./x",       "http://a/b/c/g#s/./x"},
      {"g#s/../x",      "http://a/b/c/g#s/../x"},

      {"http:g",        "http:g"}, // for strict parsers
  };
  // clang-format on

  // 5.4.  Reference Resolution Examples

  uri::absolute base("http://a/b/c/d;p?q");

  auto failures = 0;

  for (auto&& test : tests) {
    uri::reference ref(test.ref);
    auto resolved = uri::resolve_ref(base, ref);
    auto resolved_str = uri::to_string(resolved);
    if (resolved_str != test.resolved) {
      LOG(ERROR) << "##### Failure #####";
      LOG(ERROR) << "for input == " << test.ref << '\n';
      LOG(ERROR) << "ref == " << ref;
      LOG(ERROR) << "resolved == " << resolved;
      LOG(ERROR) << "should match == " << test.resolved;
      ++failures;
    }
  }

  return failures;
}

int test_comparison()
{
  auto failures = 0;

  struct test_case {
    char const* lhs;
    char const* rhs;
  };

  // clang-format off
  constexpr test_case tests[] = {
    {"http://www.example.com/",            "http://www.example.com/"},
    {"http://www.example.com/p?q",         "http://www.example.com/p?q"},
    {"http://www.example.com/p?q#f",       "http://www.example.com/p?q#f"},
    {"http://www.example.com:80/",         "http://www.example.com/"},
    {"http://www.example.com:0080/",       "http://www.example.com/"},
    {"http://WWW.EXAMPLE.COM/",            "http://www.example.com/"},
    {"http://www.example.com/./path",      "http://www.example.com/path"},
    {"http://www.example.com/1/../2/",     "http://www.example.com/2/"},
    {"example://a/b/c/%7Bfoo%7D",          "example://a/b/c/%7Bfoo%7D"},
    {"eXAMPLE://a/./b/../b/%63/%7bfoo%7d", "example://a/b/c/%7Bfoo%7D"},
  };
  // clang-format on

  for (auto&& test : tests) {
    uri::generic lhs{test.lhs, true};
    uri::generic rhs{test.rhs, true};
    if (lhs != rhs) {
      LOG(ERROR) << lhs << " != " << rhs;
      ++failures;
    }
    if (uri::to_string(lhs) != test.rhs) {
      LOG(ERROR) << uri::to_string(lhs) << " != " << test.rhs;
      LOG(ERROR) << lhs << " != " << test.rhs;
      ++failures;
    }
  }

  return failures;
}

DEFINE_string(base, "", "base URI");
DEFINE_bool(testcase, false, "print a test case for each URI");
DEFINE_bool(normalize, true, "normalize each URI");

int main(int argc, char* argv[])
{
  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  auto failures = 0;

  failures += test_comparison();
  failures += test_good();
  failures += test_bad();
  failures += test_resolution();

  {
    // the two explicit tests from RFC 3986:
    uri::components parts;
    parts.path = "/a/b/c/./../../g";
    CHECK_EQ(uri::normalize(parts), "/a/g");
    parts.path = "mid/content=5/../6";
    CHECK_EQ(uri::normalize(parts), "mid/6");
  }

  // Parse command line args as URIs.

  for (auto i = 1; i < argc; ++i) {
    uri::reference u{argv[i]};

    if (!FLAGS_base.empty()) {
      uri::absolute base(FLAGS_base);
      u = uri::reference(uri::to_string(uri::resolve_ref(base, u)));
    }

    if (FLAGS_normalize) {
      u = uri::reference(uri::normalize(u.parts()));
    }

    if (!FLAGS_testcase) {
      std::cout << "uri    == <" << u << ">\n"
                << "scheme == " << (u.scheme() ? *u.scheme() : "{}") << '\n'
                << "auth   == " << (u.authority() ? *u.authority() : "{}")
                << '\n'
                << "user   == " << (u.userinfo() ? *u.userinfo() : "{}") << '\n'
                << "host   == " << (u.host() ? *u.host() : "{}") << '\n'
                << "port   == " << (u.port() ? *u.port() : "{}") << '\n'
                << "path   == " << (u.path() ? *u.path() : "{}") << '\n'
                << "query  == " << (u.query() ? *u.query() : "{}") << '\n'
                << "frag   == " << (u.fragment() ? *u.fragment() : "{}")
                << '\n';
    }

    if (FLAGS_testcase) {
      std::cout << "  { \"" << argv[i] << "\",\n"
                << "    {";

      std::cout << "\n    /*  scheme*/ ";
      if (u.scheme())
        std::cout << "\"" << *u.scheme() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*    auth*/ ";
      if (u.authority())
        std::cout << "\"" << *u.authority() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*userinfo*/ ";
      if (u.userinfo())
        std::cout << "\"" << *u.userinfo() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*    host*/ ";
      if (u.host())
        std::cout << "\"" << *u.host() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*    port*/ ";
      if (u.port())
        std::cout << "\"" << *u.port() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*    path*/ ";
      if (u.path())
        std::cout << "\"" << *u.path() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*   query*/ ";
      if (u.query())
        std::cout << "\"" << *u.query() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    /*fragment*/ ";
      if (u.fragment())
        std::cout << "\"" << *u.fragment() << "\",";
      else
        std::cout << "{},";

      std::cout << "\n    },  \n  },\n";
    }
  }

  if (failures)
    LOG(FATAL) << "one or more tests failed";
}
