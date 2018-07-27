#define BUILDING_DLL
#include "uri.hpp"

#include <iostream>
#include <regex>

#include <glog/logging.h>

#include <fmt/format.h>

#include <idn2.h>
#include <uninorm.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
// #include <tao/pegtl/contrib/tracer.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

namespace uri {
class category_impl : public std::error_category {
public:
  category_impl() = default;
  virtual ~category_impl() {}
  virtual char const* name() const noexcept;
  virtual std::string message(int ev) const;
};

char const* category_impl::name() const noexcept
{
  static const char name[] = "uri_error";
  return name;
}

std::string category_impl::message(int ev) const
{
  switch (static_cast<error>(ev)) {
  case error::invalid_syntax:
    return "unable to parse URI";
  }
  return "unknown URI error";
}

const std::error_category& category()
{
  static category_impl category;
  return category;
}

std::error_code make_error_code(error e)
{
  return std::error_code(static_cast<int>(e), category());
}

syntax_error::syntax_error()
  : std::system_error(make_error_code(error::invalid_syntax))
{
}

syntax_error::~syntax_error() noexcept {}
} // namespace uri

// clang-format off
namespace parser {

// Rules are from <https://tools.ietf.org/html/rfc3986#appendix-A>

// The order is the rules is mostly reversed here, since we need to
// define them before use.

// UTF-8

struct UTF8_tail     : range<'\x80', '\xBF'> {};

struct UTF8_1        : range<'\x00', '\x7F'> {};

struct UTF8_2        : seq<range<'\xC2', '\xDF'>, UTF8_tail> {};

struct UTF8_3        : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, UTF8_tail>,
                           seq<range<'\xE1', '\xEC'>, rep<2, UTF8_tail>>,
                           seq<one<'\xED'>, range<'\x80', '\x9F'>, UTF8_tail>,
                           seq<range<'\xEE', '\xEF'>, rep<2, UTF8_tail>>> {};

struct UTF8_4        : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, UTF8_tail>>,
                           seq<range<'\xF1', '\xF3'>, rep<3, UTF8_tail>>,
                           seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, UTF8_tail>>> {};

struct UTF8_non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {};

//     sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                   / "*" / "+" / "," / ";" / "="
struct sub_delims    : one<'!', '$', '&', '\'', '(', ')',
                           '*', '+', ',', ';', '='> {};

//     gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
struct gen_delims    : one<':', '/', '?', '#', '[', ']', '@'> {};

//     reserved      = gen-delims / sub-delims
struct reserved      : sor<gen_delims, sub_delims> {};

// Allowing UTF-8 in the unreserved rule isn't strictly RFC-3987 since we
// make no attempt to limit the code points to exaclude the private use
// areas.  See <https://tools.ietf.org/html/rfc3987>

//    iunreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~" / ucschar
//     unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
struct unreserved    : sor<ALPHA, DIGIT, one<'-', '.', '_', '~'>, UTF8_non_ascii> {};

//     pct-encoded   = "%" HEXDIG HEXDIG
struct pct_encoded   : seq<one<'%'>, HEXDIG, HEXDIG> {};

//     pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
struct pchar         : sor<unreserved, pct_encoded, sub_delims, one<':', '@'>> {};

//     fragment      = *( pchar / "/" / "?" )
struct fragment      : star<sor<pchar, one<'/', '?'>>> {};

//     query         = *( pchar / "/" / "?" )
struct query         : star<sor<pchar, one<'/', '?'>>> {};

//     segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//                   ; non-zero-length segment without any colon ":"
struct segment_nz_nc : plus<sor<unreserved, pct_encoded, sub_delims, one<'@'>>> {};

//     segment-nz    = 1*pchar
struct segment_nz    : plus<pchar> {};

//     segment       = *pchar
struct segment       : star<pchar> {};

//     path-empty    = 0<pchar>
struct path_empty    : success {};

//     path-rootless = segment-nz *( "/" segment )
struct path_rootless : seq<segment_nz, star<seq<one<'/'>, segment>>> {};

//     path-noscheme = segment-nz-nc *( "/" segment )
struct path_noscheme : seq<segment_nz_nc, star<seq<one<'/'>, segment>>> {};

//     path-absolute = "/" [ segment-nz *( "/" segment ) ]
struct path_absolute : seq<one<'/'>, opt<seq<segment_nz, star<seq<one<'/'>, segment>>>>> {};

//     path-abempty  = *( "/" segment )
struct path_abempty  : star<seq<one<'/'>, segment>> {};

//     path          = path-abempty    ; begins with "/" or is empty
//                   / path-absolute   ; begins with "/" but not "//"
//                   / path-noscheme   ; begins with a non-colon segment
//                   / path-rootless   ; begins with a segment
//                   / path-empty      ; zero characters
// struct path       : sor<path_abempty,
//                         path_absolute,
//                         path_noscheme,
//                         path_rootless,
//                         path_empty> {};

/////////////////////////////////////////////////////////////////////////////

// The definition of reg-name is where I stray from the (very loose)
// grammar of RFC-3986 and apply the stricter rules of RFC-1123 plus
// the UTF-8 of RFC-3987.

// We allow very a very limited set of percent encoded characters in
// the reg_name part: just letter, digit, hyphen, and dot.  If you
// want Unicode in your host part, use UTF-8 or punycode.  You can't
// percent encode it.

struct pct_let_dig   : seq<one<'%'>,
                           sor<// ALPHA    x41 -> x5A
                               seq<one<'4'>, range<'1','9'>>,
                               seq<one<'4'>, range<'A','F'>>,
                               seq<one<'4'>, range<'a','f'>>,
                               seq<one<'5'>, range<'0','9'>>,
                               seq<one<'5'>, one<'A'>>,
                               seq<one<'5'>, one<'a'>>,
                               // DIGIT    x30 -> x39
                               seq<one<'3'>, range<'0','9'>>
                             >
                           > {};

struct u_let_dig     : sor<ALPHA, DIGIT, UTF8_non_ascii, pct_let_dig> {};

struct dash          : sor<one<'-'>, TAOCPP_PEGTL_ISTRING("%2D")> {};

struct u_ldh_tail    : star<sor<seq<plus<dash>, u_let_dig>, u_let_dig>> {};

struct u_label       : seq<u_let_dig, u_ldh_tail> {};

struct dot           : sor<one<'.'>, TAOCPP_PEGTL_ISTRING("%2E")> {};

// An Internet (RFC-1123) style hostname:
struct reg_name      : list_tail<u_label, dot> {};

// All that is required for 3986 is the following:
//       reg-name    = *( unreserved / pct-encoded / sub-delims )
//struct reg_name    : star<sor<unreserved, pct_encoded, sub_delims>> {};

/////////////////////////////////////////////////////////////////////////////

//     dec-octet     = DIGIT                 ; 0-9
//                   / %x31-39 DIGIT         ; 10-99
//                   / "1" 2DIGIT            ; 100-199
//                   / "2" %x30-34 DIGIT     ; 200-249
//                   / "25" %x30-35          ; 250-255
struct dec_octet     : sor<seq<string<'2','5'>, range<'0','5'>>,
                           seq<one<'2'>, range<'0','4'>, DIGIT>,
                           seq<one<'1'>, DIGIT, DIGIT>,
                           seq<range<'1','9'>, DIGIT>,
                           DIGIT> {};

//     IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
struct IPv4address   : seq<dec_octet, one<'.'>, dec_octet, one<'.'>, dec_octet, one<'.'>, dec_octet> {};
struct IPv4address_eof : seq<IPv4address, eof> {};

//     h16           = 1*4HEXDIG
//                   ; 16 bits of address represented in hexadecimal
struct h16           : rep_min_max<1, 4, HEXDIG> {};

//     ls32          = ( h16 ":" h16 ) / IPv4address
//                   ; least-significant 32 bits of address
struct ls32          : sor<seq<h16, one<':'>, h16>, IPv4address> {};

//     IPv6address   =                            6( h16 ":" ) ls32
//                   /                       "::" 5( h16 ":" ) ls32
//                   / [               h16 ] "::" 4( h16 ":" ) ls32
//                   / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//                   / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//                   / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//                   / [ *4( h16 ":" ) h16 ] "::"              ls32
//                   / [ *5( h16 ":" ) h16 ] "::"              h16
//                   / [ *6( h16 ":" ) h16 ] "::"

struct IPv6address   : sor<seq<                                               rep<6, h16, one<':'>>, ls32>,
                           seq<                                     two<':'>, rep<5, h16, one<':'>>, ls32>,
                           seq<opt<h16                           >, two<':'>, rep<4, h16, one<':'>>, ls32>,
                           seq<opt<h16,     opt<   one<':'>, h16>>, two<':'>, rep<3, h16, one<':'>>, ls32>,
                           seq<opt<h16, rep_opt<2, one<':'>, h16>>, two<':'>, rep<2, h16, one<':'>>, ls32>,
                           seq<opt<h16, rep_opt<3, one<':'>, h16>>, two<':'>,        h16, one<':'>,  ls32>,
                           seq<opt<h16, rep_opt<4, one<':'>, h16>>, two<':'>,                        ls32>,
                           seq<opt<h16, rep_opt<5, one<':'>, h16>>, two<':'>,                        h16>,
                           seq<opt<h16, rep_opt<6, one<':'>, h16>>, two<':'>>> {};

//     IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
struct IPvFuture     : seq<one<'v'>, plus<HEXDIG>, one<'.'>, plus<sor<unreserved, sub_delims, one<':'>>>> {};

//     IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
struct IP_literal    : seq<one<'['>, sor<IPv6address, IPvFuture>, one<']'>> {};
struct IP_literal_eof : seq<IP_literal, eof> {};

//     port          = *DIGIT
struct port          : star<DIGIT> {};

//     host          = IP-literal / IPv4address / reg-name
struct host          : sor<IP_literal, IPv4address, reg_name> {};

//     userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
struct userinfo      : star<sor<unreserved, pct_encoded, sub_delims, one<':'>>> {};

// Use userinfo_at rule to trigger setting userinfo field only after '@' char is found.
struct userinfo_at   : seq<userinfo, one<'@'>> {};

//     authority     = [ userinfo "@" ] host [ ":" port ]
struct authority     : seq<opt<userinfo_at>, host, opt<seq<one<':'>, port>>> {};

//     scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
struct scheme        : seq<ALPHA, star<sor<ALPHA, DIGIT, one<'+', '-', '.'>>>> {};

//     relative-part = "//" authority path-abempty
//                   / path-absolute
//                   / path-noscheme
//                   / path-empty
struct relative_part : sor<seq<two<'/'>, authority, path_abempty>,
                           path_absolute,
                           path_noscheme,
                           path_empty> {};

//     relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
struct relative_ref  : seq<relative_part, opt<seq<one<'?'>, query>>, opt<seq<one<'#'>, fragment>>> {};
struct relative_ref_eof : seq<relative_ref, eof> {};

//     hier-part     = "//" authority path-abempty
//                   / path-absolute
//                   / path-rootless
//                   / path-empty
struct hier_part     : sor<seq<two<'/'>, authority, path_abempty>,
                           path_absolute,
                           path_rootless,
                           path_empty> {};

//     absolute-URI  = scheme ":" hier-part [ "?" query ]
struct absolute_URI  : seq<scheme, one<':'>, hier_part, opt<seq<one<'?'>, query>>> {};
struct absolute_URI_eof : seq<absolute_URI, eof> {};

//     URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
struct URI           : seq<absolute_URI, opt<seq<one<'#'>, fragment>>> {};
struct URI_eof       : seq<URI, eof> {};

//     URI-reference = URI / relative-ref
struct URI_reference : sor<URI, relative_ref> {};
struct URI_reference_eof : seq<URI_reference, eof> {};

// clang-format on

template <typename Rule> struct action : nothing<Rule> {
};

template <> struct action<scheme> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.scheme = std::string_view(begin(in), size(in));
  }
};

template <> struct action<authority> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.authority = std::string_view(begin(in), size(in));
  }
};

template <> struct action<path_abempty> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.path = std::string_view(begin(in), size(in));
  }
};

template <> struct action<path_absolute> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.path = std::string_view(begin(in), size(in));
  }
};

template <> struct action<path_rootless> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.path = std::string_view(begin(in), size(in));
  }
};

template <> struct action<query> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.query = std::string_view(begin(in), size(in));
  }
};

template <> struct action<fragment> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.fragment = std::string_view(begin(in), size(in));
  }
};

// The _at rule gives us userinfo + '@', so remove the at.

template <> struct action<userinfo_at> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    auto ui = std::string_view(begin(in), size(in));
    if ((size(ui) >= 1) && (ui.back() == '@')) {
      ui.remove_suffix(1);
      parts.userinfo = ui;
    }
  }
};

template <> struct action<host> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.host = std::string_view(begin(in), size(in));
  }
};

template <> struct action<port> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.port = std::string_view(begin(in), size(in));
  }
};
} // namespace parser

namespace uri {
DLL_PUBLIC bool parse_generic(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<parser::URI_eof, parser::action>(in, parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_relative_ref(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<parser::relative_ref_eof, parser::action>(in, parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_reference(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<parser::URI_reference_eof, parser::action>(in, parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_absolute(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<parser::absolute_URI_eof, parser::action>(in, parts)) {
    return true;
  }
  return false;
}

std::string to_string(uri const& uri_in) { return to_string(uri_in.parts()); }

std::string to_string(components const& uri)
{
  std::ostringstream os;
  os << uri;
  return os.str();
}

namespace {
// clang-format off

bool constexpr isunreserved(unsigned char in)
{
  switch (in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f': case 'g': case 'h': case 'i': case 'j':
    case 'k': case 'l': case 'm': case 'n': case 'o':
    case 'p': case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F': case 'G': case 'H': case 'I': case 'J':
    case 'K': case 'L': case 'M': case 'N': case 'O':
    case 'P': case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case '-': case '.': case '_': case '~':
      return true;
    default:
      break;
  }
  return false;
}

bool constexpr ishexdigit(unsigned char in)
{
  switch (in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f':
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F':
      return true;
    default:
      break;
  }
  return false;
}

unsigned char constexpr hexdigit2bin(unsigned char in)
{
  switch (in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return (in - '0');
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f':
      return 10 + (in - 'a');
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F':
      break;
  }
  return 10 + (in - 'A');
}
// clang-format on

std::string remove_pct_encoded_unreserved(std::string_view string)
{
  fmt::memory_buffer out;

  for (auto s = begin(string); s < end(string); ++s) {
    auto ch = *s;
    if (ch == '%') {
      if ((s + 3 < end(string)) && ishexdigit(s[1]) && ishexdigit(s[2])) {
        auto pct_ch = (hexdigit2bin(s[1]) << 4) + hexdigit2bin(s[2]);
        if (isunreserved(pct_ch)) {
          fmt::format_to(out, "{}", char(pct_ch));
        }
        else {
          fmt::format_to(out, "%{:02X}", pct_ch);
        }
        s += 2;
        continue;
      }
    }
    fmt::format_to(out, "{}", ch);
  }

  return fmt::to_string(out);
}

bool starts_with(std::string_view str, std::string_view prefix)
{
  if (str.size() >= prefix.size())
    if (str.compare(0, prefix.size(), prefix) == 0)
      return true;
  return false;
}

// <https://tools.ietf.org/html/rfc3986#section-5.2.4>

// 5.2.4.  Remove Dot Segments

std::string remove_dot_segments(std::string input)
{
  std::string output;

  auto constexpr path_segment_re_str = "^(/?[^/]*)";
  auto const path_segment_re{std::regex{path_segment_re_str}};

  while (!input.empty()) {
    // A.
    if (starts_with(input, "../")) {
      input.erase(0, 3);
    }
    else if (starts_with(input, "./")) {
      input.erase(0, 2);
    }
    else {
      // B.
      if (starts_with(input, "/./")) {
        input.erase(0, 3);
        input.insert(0, "/");
      }
      else if (input == "/.") {
        input.erase(0, 2);
        input.insert(0, "/");
      }
      else {
        // C.
        if (starts_with(input, "/../")) {
          input.erase(0, 4);
          input.insert(0, "/");
          // remove last segment from output
          auto last = output.rfind("/");
          if (last != std::string::npos) {
            output.erase(output.begin() + last, output.end());
          }
        }
        else if (input == "/..") {
          input.erase(0, 3);
          input.insert(0, "/");
          // remove last segment from output
          auto last = output.rfind("/");
          if (last != std::string::npos) {
            output.erase(output.begin() + last, output.end());
          }
        }
        else {
          // D.
          if (input == ".") {
            input.erase(0, 1);
          }
          else if (input == "..") {
            input.erase(0, 2);
          }
          else {
            std::smatch sm;
            if (std::regex_search(input, sm, path_segment_re)) {
              output += sm.str();
              input.erase(0, sm.str().length());
            }
            else {
              LOG(FATAL) << "no match, we'll be looping forever";
            }
          }
        }
      }
    }
  }

  return output;
}

size_t constexpr max_length = 255;

std::string_view remove_trailing_dot(std::string_view a)
{
  if (a.length() && ('.' == a.back())) {
    a.remove_suffix(1);
  }
  return a;
}

// Normalization Form KC (NFKC) Compatibility Decomposition, followed
// by Canonical Composition, see <http://unicode.org/reports/tr15/>

std::string nfkc(std::string_view str)
{
  size_t length = max_length;
  char bfr[max_length];
  if (str.length() > max_length) {
    throw std::runtime_error("hostname too long");
  }
  auto udata = reinterpret_cast<uint8_t const*>(str.data());
  auto ubfr = reinterpret_cast<uint8_t*>(bfr);
  if (u8_normalize(UNINORM_NFKC, udata, str.size(), ubfr, &length) == nullptr) {
    throw std::runtime_error("u8_normalize failure");
  }
  return std::string{bfr, length};
}

bool is_IPv4address(std::string_view x)
{
  auto in{memory_input<>{x.data(), x.size(), "maybe-IPv4address"}};
  if (tao::pegtl::parse<parser::IPv4address_eof, parser::action>(in)) {
    return true;
  }
  return false;
}

bool is_IP_literal(std::string_view x)
{
  auto in{memory_input<>{x.data(), x.size(), "maybe-IP_literal"}};
  if (tao::pegtl::parse<parser::IP_literal_eof, parser::action>(in)) {
    return true;
  }
  return false;
}

std::string normalize_host(std::string_view host)
{
  host = remove_trailing_dot(host);

  auto norm_host = remove_pct_encoded_unreserved(host);

  norm_host = nfkc(norm_host);

  char* ptr = nullptr;
  auto code = idn2_to_ascii_8z(norm_host.data(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    throw std::runtime_error(idn2_strerror(code));
  }
  norm_host = ptr;
  idn2_free(ptr);

  // At this point, we have a (normalized) ascii norm_host.  Continue
  // on to get the UTF-8 version.

#ifdef PREFER_UNICODE_HOSTNAME
  ptr = nullptr;
  code = idn2_to_unicode_8z8z(norm_host.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    throw std::runtime_error(idn2_strerror(code));
  }
  norm_host = ptr;
  idn2_free(ptr);
#endif

  return norm_host;
}
} // namespace

DLL_PUBLIC std::string normalize(components uri)
{
  std::string scheme;
  std::string host;

  // Normalize the scheme.
  scheme.reserve(uri.scheme.length());
  std::transform(begin(uri.scheme), end(uri.scheme), std::back_inserter(scheme),
                 [](unsigned char c) { return std::tolower(c); });
  uri.scheme = scheme;

  // Normalize the host name.
  if (!(is_IPv4address(uri.host) || is_IP_literal(uri.host))) {
    host = normalize_host(uri.host);
    uri.host = host;
  }

  // we'll want to remove default port numbers

  // Rebuild authority from user@host:port triple.
  std::stringstream auth;
  if (!uri.userinfo.empty())
    auth << uri.userinfo << '@';

  if (!uri.host.empty())
    auth << uri.host;

  if (!uri.port.empty())
    auth << ':' << uri.port;

  auto auth_str = auth.str();

  if (!auth_str.empty())
    uri.authority = auth_str;

  // Normalize the path.
  auto path = remove_dot_segments(remove_pct_encoded_unreserved(uri.path));
  uri.path = path;

  return to_string(uri);
}
} // namespace uri

// https://tools.ietf.org/html/rfc3986#section-5.3

// 5.3.  Component Recomposition

DLL_PUBLIC std::ostream& operator<<(std::ostream& os,
                                    uri::components const& uri)
{
  if (!uri.scheme.empty()) {
    os << uri.scheme << ':';
  }

  if (!uri.authority.empty()) {
    os << "//" << uri.authority;
  }

  if (!uri.path.empty()) {
    os << uri.path;
  }

  if (!uri.query.empty()) {
    os << '?' << uri.query;
  }

  if (!uri.fragment.empty()) {
    os << '#' << uri.fragment;
  }

  return os;
}

DLL_PUBLIC std::ostream& operator<<(std::ostream& os, uri::uri const& uri_in)
{
  return os << uri_in.parts();
}
