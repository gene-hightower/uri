#define BUILDING_DLL
#include "uri.hpp"

#include <iostream>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <idn2.h>
#include <uninorm.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>

#include <tao/pegtl.hpp>

using tao::pegtl::any;
using tao::pegtl::eof;
using tao::pegtl::list_tail;
using tao::pegtl::memory_input;
using tao::pegtl::not_at;
using tao::pegtl::nothing;
using tao::pegtl::one;
using tao::pegtl::opt;
using tao::pegtl::plus;
using tao::pegtl::range;
using tao::pegtl::rep;
using tao::pegtl::rep_min_max;
using tao::pegtl::rep_opt;
using tao::pegtl::seq;
using tao::pegtl::sor;
using tao::pegtl::star;
using tao::pegtl::string;
using tao::pegtl::success;
using tao::pegtl::two;

#include <tao/pegtl/contrib/abnf.hpp>

using tao::pegtl::abnf::ALPHA;
using tao::pegtl::abnf::DIGIT;
using tao::pegtl::abnf::HEXDIG;

#include <glog/logging.h>

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
namespace uri_internal {

// Rules are from <https://tools.ietf.org/html/rfc3986#appendix-A>

// The order is the rules is mostly reversed here, since we need to
// define them before use.

// UTF-8 is from RFC-3987

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

// Updated by Errata ID: 2033
//     path-empty    = ""
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

// We allow a very limited set of percent encoded characters in the
// reg_name part: just letter, digit, hyphen, and dot.  If you want
// Unicode in your host part, use UTF-8 or punycode: you can't percent
// encode it.

struct pct_let_dig   : seq<one<'%'>,
                           sor<// ALPHA UC  x41 -> x5A
                               seq<one<'4'>, range<'1','9'>>,
                               seq<one<'4'>, range<'A','F'>>,
                               seq<one<'4'>, range<'a','f'>>,
                               seq<one<'5'>, range<'0','9'>>,
                               seq<one<'5'>, one<'A'>>,
                               seq<one<'5'>, one<'a'>>,
                               // ALPHA LC  x61 -> x7A
                               seq<one<'6'>, range<'1','9'>>,
                               seq<one<'6'>, range<'A','F'>>,
                               seq<one<'6'>, range<'a','f'>>,
                               seq<one<'7'>, range<'0','9'>>,
                               seq<one<'7'>, one<'A'>>,
                               seq<one<'7'>, one<'a'>>,
                               // DIGIT     x30 -> x39
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

// All that is required for 3986 (as updated by Errata ID: 4942) is the following:

//       reg-name    = *( unreserved / pct-encoded / "-" / "." )
//struct reg_name    : star<sor<unreserved, pct_encoded, one<'-'>, one<'.'>>> {};

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

//       IP-literal  = "[" ( IPv6address / IPvFuture  ) "]"
//struct IP_literal  : seq<one<'['>, sor<IPv6address, IPvFuture>, one<']'>> {};

// RFC 6874 replaced the above rule with:

//     ZoneID        = 1*( unreserved / pct-encoded )
struct ZoneID        : plus<sor<unreserved, pct_encoded>> {};

//     IPv6addrz     = IPv6address "%25" ZoneID
struct IPv6addrz     : seq<IPv6address, one<'%'>, ZoneID> {};

//     IP-literal    = "[" ( IPv6address / IPv6addrz / IPvFuture  ) "]"
//     or maybe just:
//     IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
struct IP_literal    :  seq<one<'['>, sor<IPv6address, IPvFuture>, one<']'>> {};

struct IP_literal_eof: seq<IP_literal, eof> {};

//     port          = *DIGIT
// But actually, in the IP world, ports are unsigned 16 bit numbers.
  struct port          : sor<seq<string<'6','5','5','3'>, range<'0','5'>>,
                             seq<string<'6','5','5'>, range<'0','2'>, DIGIT>,
                             seq<string<'6','5'>, range<'0', '4'>, rep<2, DIGIT>>,
                             seq<one<'6'>, range<'0', '4'>, rep<3, DIGIT>>,
                             seq<range<'0','5'>, rep<4, DIGIT>>,
                             rep_min_max<0, 4, DIGIT>,
                             TAOCPP_PEGTL_STRING("00000")
                             > {};

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

// Use scheme_colon rule to trigger setting scheme field only after ':' char is found.
struct scheme_colon  : seq<scheme, one<':'>> {};

//     relative-part = "//" authority path-abempty
//                   / path-absolute
//                   / path-noscheme
//                   / path-abempty    ; this was added in Errata ID: 5428
//                   / path-empty
struct relative_part : sor<seq<two<'/'>, authority, path_abempty>,
                           path_absolute,
                           path_noscheme,
                           path_abempty,
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
struct absolute_URI  : seq<scheme_colon, hier_part, opt<seq<one<'?'>, query>>> {};
struct absolute_URI_eof : seq<absolute_URI, eof> {};

//     URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
struct URI           : seq<scheme_colon, hier_part, opt<seq<one<'?'>, query>>, opt<seq<one<'#'>, fragment>>> {};
struct URI_eof       : seq<URI, eof> {};

//     URI-reference = URI / relative-ref
struct URI_reference : sor<URI, relative_ref> {};
struct URI_reference_eof : seq<URI_reference, eof> {};

struct path_segment : seq<opt<one<'/'>>, seq<star<not_at<one<'/'>>, not_at<eof>, any>>> {};

// clang-format on

template <typename Rule> struct action : nothing<Rule> {
};

template <> struct action<scheme_colon> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    auto sc = std::string_view(begin(in), size(in));
    CHECK((size(sc) >= 1) && (sc.back() == ':'));
    sc.remove_suffix(1);
    parts.scheme = sc;
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

template <> struct action<path_empty> {
  template <typename Input>
  static void apply(Input const& in, uri::components& parts)
  {
    parts.path = std::string{};
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

template <> struct action<path_noscheme> {
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
    CHECK((size(ui) >= 1) && (ui.back() == '@'));
    ui.remove_suffix(1);
    parts.userinfo = ui;
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

template <> struct action<path_segment> {
  template <typename Input>
  static void apply(Input const& in, std::string& path_seg)
  {
    path_seg = std::string_view(begin(in), size(in));
  }
};
} // namespace uri_internal

namespace uri {
DLL_PUBLIC bool parse_generic(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<uri_internal::URI_eof, uri_internal::action>(in,
                                                                     parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_relative_ref(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<uri_internal::relative_ref_eof, uri_internal::action>(
          in, parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_reference(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<uri_internal::URI_reference_eof, uri_internal::action>(
          in, parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_absolute(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<uri_internal::absolute_URI_eof, uri_internal::action>(
          in, parts)) {
    return true;
  }
  return false;
}

std::string to_string(components const& uri)
{
  std::ostringstream os;
  os << uri;
  return os.str();
}

bool uri::operator<(uri const& rhs) const
{
  if (form_ != rhs.form_) {
    LOG(FATAL) << "forms don't match for these URIs: " << *this << " " << rhs;
  }
  return uri_ < rhs.uri_;
}

bool uri::operator==(uri const& rhs) const
{
  if (form_ != rhs.form_) {
    LOG(FATAL) << "forms don't match for these URIs: " << *this << " " << rhs;
  }
  return uri_ == rhs.uri_;
}

generic::generic(std::string uri_in, bool norm)
{
  static_assert(sizeof(generic) == sizeof(uri));
  uri_ = uri_in;
  if (!parse_generic(uri_, parts_)) {
    throw syntax_error();
  }
  if (norm) {
    uri_ = normalize(parts_);
    parts_ = components{};
    CHECK(parse_generic(uri_, parts_));
    form_ = form::normalized;
  }
}

generic::generic(components const& uri_in, bool norm)
  : generic(norm ? normalize(uri_in) : to_string(uri_in), false)
{
  static_assert(sizeof(generic) == sizeof(uri));
  form_ = norm ? form::normalized : form::unnormalized;
}

absolute::absolute(std::string uri_in, bool norm)
{
  static_assert(sizeof(absolute) == sizeof(uri));
  uri_ = uri_in;
  if (!parse_absolute(uri_, parts_)) {
    throw syntax_error();
  }
  if (norm) {
    uri_ = normalize(parts_);
    parts_ = components{};
    CHECK(parse_absolute(uri_, parts_));
    form_ = form::normalized;
  }
}

absolute::absolute(components const& uri_in, bool norm)
  : absolute(norm ? normalize(uri_in) : to_string(uri_in), false)
{
  static_assert(sizeof(absolute) == sizeof(uri));
  form_ = norm ? form::normalized : form::unnormalized;
}

reference::reference(std::string uri_in, bool norm)
{
  static_assert(sizeof(reference) == sizeof(uri));
  uri_ = uri_in;
  if (!parse_reference(uri_, parts_)) {
    throw syntax_error();
  }
  if (norm) {
    uri_ = normalize(parts_);
    parts_ = components{};
    CHECK(parse_reference(uri_, parts_));
    form_ = form::normalized;
  }
}

reference::reference(components const& uri_in, bool norm)
  : reference(norm ? normalize(uri_in) : to_string(uri_in), false)
{
  static_assert(sizeof(reference) == sizeof(uri));
  form_ = norm ? form::normalized : form::unnormalized;
}

namespace {

bool constexpr isunreserved(unsigned char in)
{
  // clang-format off
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
  // clang-format on
}

bool constexpr ishexdigit(unsigned char in)
{
  // clang-format off
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
  // clang-format on
}

unsigned char constexpr hexdigit2bin(unsigned char in)
{
  // clang-format off
  switch (in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return (in - '0');
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f':
      return 10 + (in - 'a');
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F':
      return 10 + (in - 'A');
  }
  return 0;
  // clang-format on
}

std::string normalize_pct_encoded(std::string_view string)
{
  fmt::memory_buffer out;

  for (auto s = begin(string); s < end(string); ++s) {
    auto ch = *s;
    if (ch == '%') {
      if ((s + 3 <= end(string)) && ishexdigit(s[1]) && ishexdigit(s[2])) {
        auto pct_ch = 0x10 * hexdigit2bin(s[1]) + hexdigit2bin(s[2]);
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
    return str.compare(0, prefix.size(), prefix) == 0;
  return false;
}

bool ends_with(std::string_view str, std::string_view suffix)
{
  if (str.size() >= suffix.size())
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix)
           == 0;
  return false;
}

std::string view_to_string(std::string_view view)
{
  return std::string(view.data(), view.length());
}

std::string all_but_the_last(std::string_view path)
{
  // …
  // excluding any characters after the right-most "/" in the base URI
  // path, or excluding the entire base URI path if it does not contain
  // any "/" characters).

  auto x = path.rfind('/');
  if (x == std::string_view::npos)
    return std::string{};
  return std::string(path.data(), x + 1);
}

// <https://tools.ietf.org/html/rfc3986#section-5.2.3>

// 5.2.3.  Merge Paths

std::string merge(components const& base_parts, components const& ref_parts)

{
  // Updated by Errata ID: 4789

  // o  If the base URI has a defined authority component and an empty
  //    path, or if the base URI's path is ending with "/..", then return
  //    a string consisting of base's path concatenated with "/" and then
  //    concatenated with the reference's path; otherwise,

  if ((base_parts.authority && base_parts.path->empty())
      || ends_with(*base_parts.path, "/..")) {
    return "/" + view_to_string(*ref_parts.path);
  }

  // o  return a string consisting of the reference's path component
  //    appended to all but the last segment of the base URI's path…

  return all_but_the_last(*base_parts.path) + view_to_string(*ref_parts.path);
}

// <https://tools.ietf.org/html/rfc3986#section-5.2.4>

// 5.2.4.  Remove Dot Segments

std::string remove_dot_segments(std::string_view input)
{
  std::string output;
  output.reserve(input.length());

  while (!input.empty()) {
    // A.
    if (starts_with(input, "../")) {
      input.remove_prefix(3);
      continue;
    }
    if (starts_with(input, "./")) {
      input.remove_prefix(2);
      continue;
    }

    // B.
    if (starts_with(input, "/./")) {
      input.remove_prefix(2);
      continue;
    }
    if (input == "/.") {
      input = "/";
      continue;
    }

    // C.
    if (starts_with(input, "/../")) {
      input.remove_prefix(3);
      // remove last segment from output
      auto last = output.rfind("/");
      if (last != std::string::npos) {
        output.erase(output.begin() + last, output.end());
      }
      continue;
    }
    if (input == "/..") {
      input = "/";
      // remove last segment from output
      auto last = output.rfind("/");
      if (last != std::string::npos) {
        output.erase(output.begin() + last, output.end());
      }
      continue;
    }

    // D.
    if (input == ".") {
      input = "";
      continue;
    }
    if (input == "..") {
      input = "";
      continue;
    }

    auto in{memory_input<>{input.data(), input.size(), "path-segment"}};

    std::string path_seg;
    if (tao::pegtl::parse<uri_internal::path_segment, uri_internal::action>(
            in, path_seg)) {
      output += path_seg;
      input.remove_prefix(path_seg.length());
    }
    else {
      LOG(FATAL) << "no match, we'll be looping forever";
    }
  }

  return output;
}

std::string_view remove_trailing_dot(std::string_view a)
{
  if (a.length() && ('.' == a.back())) {
    a.remove_suffix(1);
  }
  return a;
}

// Normalization Form KC (NFKC) Compatibility Decomposition, followed
// by Canonical Composition, see <http://unicode.org/reports/tr15/>

size_t constexpr max_length = 255;

std::string nfkc(std::string_view str)
{
  if (str.length() > max_length) {
    throw std::runtime_error("hostname too long");
  }
  size_t length = max_length;
  char bfr[max_length];
  auto const udata = reinterpret_cast<uint8_t const*>(str.data());
  auto const ubfr = reinterpret_cast<uint8_t*>(bfr);
  if (u8_normalize(UNINORM_NFKC, udata, str.size(), ubfr, &length) == nullptr) {
    throw std::runtime_error("u8_normalize failure");
  }
  return std::string{bfr, length};
}

bool is_IPv4address(std::string_view x)
{
  auto in{memory_input<>{x.data(), x.size(), "maybe-IPv4address"}};
  if (tao::pegtl::parse<uri_internal::IPv4address_eof, uri_internal::action>(
          in)) {
    return true;
  }
  return false;
}

bool is_IP_literal(std::string_view x)
{
  auto in{memory_input<>{x.data(), x.size(), "maybe-IP_literal"}};
  if (tao::pegtl::parse<uri_internal::IP_literal_eof, uri_internal::action>(
          in)) {
    return true;
  }
  return false;
}

std::string normalize_host(std::string_view host)
{
  host = remove_trailing_dot(host);

  auto norm_host = normalize_pct_encoded(host);

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

  //#ifdef PREFER_UNICODE_HOSTNAME
  ptr = nullptr;
  code = idn2_to_unicode_8z8z(norm_host.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    throw std::runtime_error(idn2_strerror(code));
  }
  norm_host = ptr;
  idn2_free(ptr);
  //#endif

  return norm_host;
}

} // namespace

DLL_PUBLIC std::string normalize(components uri)
{
  std::string scheme;
  std::string authority;
  std::string userinfo;
  std::string host;
  std::string port;
  std::string path;
  std::string query;
  std::string fragment;

  // Normalize the scheme.
  if (uri.scheme) {
    scheme.reserve(uri.scheme->size());
    std::transform(begin(*uri.scheme), end(*uri.scheme),
                   std::back_inserter(scheme),
                   [](unsigned char c) { return std::tolower(c); });
    uri.scheme = scheme;
  }

  // Normalize the host name.
  if (uri.host) {
    if (!(is_IPv4address(*uri.host) || is_IP_literal(*uri.host))) {
      host = normalize_host(*uri.host);
      uri.host = host;
    }
  }

  //-----------------------------------------------------------------------------

  // https://url.spec.whatwg.org/#url-miscellaneous

  struct special_scheme {
    char const* scheme;
    char const* default_path;
    uint16_t default_port;
  };

  // Very short list of scheme specific default port numbers.
  // clang-format off
  special_scheme special[] = {
      {"ftp",    "",  21},
      {"gopher", "",  70},
      {"http",  "/",  80},
      {"https", "/", 443},
      {"ws",     "",  80},
      {"wss",    "", 443},
  };
  // clang-format on

  for (auto&& spc : special) {
    if (uri.scheme == spc.scheme) {
      if (uri.port && !uri.port->empty()) {
        auto p = strtoul(uri.port->data(), nullptr, 10);
        if (p == spc.default_port) {
          uri.port = {};
        }
      }
      if (uri.port && uri.port->empty()) {
        uri.port = {};
      }

      if (uri.path && uri.path->empty()) {
        uri.path = spc.default_path;
      }

      break;
    }
  }

  // remove leading zeros
  if (uri.port && !uri.port->empty()) {
    auto p = strtoul(uri.port->data(), nullptr, 10);
    port = fmt::format("{}", p);
    uri.port = port;
  }

  // The whole list at:
  // <https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml>
  // has like 288 schemes to deal with, of which 95 are "Permanent."

  //-----------------------------------------------------------------------------

  // Rebuild authority from user@host:port triple.
  std::stringstream authstream;
  if (uri.userinfo)
    authstream << *uri.userinfo << '@';

  if (uri.host)
    authstream << *uri.host;

  if (uri.port)
    authstream << ':' << *uri.port;

  if (uri.userinfo || uri.host || uri.port) {
    authority = authstream.str();
    uri.authority = authority;
  }

  // Normalize the path.
  if (uri.path) {
    path = remove_dot_segments(normalize_pct_encoded(*uri.path));
    uri.path = path;
  }

  if (uri.query) {
    query = normalize_pct_encoded(*uri.query);
    uri.query = query;
  }

  if (uri.fragment) {
    fragment = normalize_pct_encoded(*uri.fragment);
    uri.fragment = fragment;
  }

  return to_string(uri);
}

DLL_PUBLIC uri resolve_ref(absolute const& base, reference const& ref)
{
  std::string path;

  // 5.2.  Relative Resolution

  if (ref.empty()) {
    return base;
  }

  components const& base_parts = base.parts();
  components const& ref_parts = ref.parts();

  components target_parts;

  // if defined(R.scheme) then

  if (ref_parts.scheme) {

    // T.scheme    = R.scheme;
    target_parts.scheme = *ref_parts.scheme;

    // T.authority = R.authority;
    if (ref_parts.authority) {
      target_parts.authority = *ref_parts.authority;
    }

    if (ref_parts.path) {
      path = remove_dot_segments(*ref_parts.path);
      target_parts.path = path;
    }

    if (ref_parts.query) {
      target_parts.query = *ref_parts.query;
    }
  }
  else {
    if (ref_parts.authority) {
      target_parts.authority = *ref_parts.authority;
      if (ref_parts.path) {
        path = remove_dot_segments(*ref_parts.path);
        target_parts.path = path;
      }
      target_parts.query = ref_parts.query;
    }
    else {

      if (ref_parts.path == "") {
        target_parts.path = base_parts.path;
        if (ref_parts.query) {
          target_parts.query = ref_parts.query;
        }
        else {
          target_parts.query = base_parts.query;
        }
      }
      else {
        if (starts_with(*ref_parts.path, "/")) {
          if (ref_parts.path) {
            path = remove_dot_segments(*ref_parts.path);
            target_parts.path = path;
          }
        }
        else {
          // T.path = merge(Base.path, R.path);
          // T.path = remove_dot_segments(T.path);
          path = remove_dot_segments(merge(base_parts, ref_parts));
          target_parts.path = path;
        }

        // T.query = R.query;
        target_parts.query = ref_parts.query;
      }

      // T.authority = Base.authority;
      target_parts.authority = base_parts.authority;
    }

    // T.scheme = Base.scheme;
    target_parts.scheme = base_parts.scheme;
  }

  // T.fragment = R.fragment;
  if (ref_parts.fragment) {
    target_parts.fragment = *ref_parts.fragment;
  }

  return generic(target_parts);
}

} // namespace uri

// <https://tools.ietf.org/html/rfc3986#section-5.3>

// 5.3.  Component Recomposition

DLL_PUBLIC std::ostream& operator<<(std::ostream& os,
                                    uri::components const& uri)
{
  if (uri.scheme) {
    os << *uri.scheme << ':';
  }

  // The individual parts take precedence over the single authority.

  if (uri.userinfo || uri.host || uri.port) {
    os << "//";

    if (uri.userinfo)
      os << *uri.userinfo << '@';

    // Host is never undefined, but perhaps zero length.
    if (uri.host)
      os << *uri.host;

    if (uri.port)
      os << ':' << *uri.port;
  }
  else if (uri.authority) {
    os << "//" << *uri.authority;
  }

  if (uri.path) {
    os << *uri.path;
  }

  if (uri.query) {
    os << '?' << *uri.query;
  }

  if (uri.fragment) {
    os << '#' << *uri.fragment;
  }

  return os;
}

DLL_PUBLIC std::ostream& operator<<(std::ostream& os, uri::uri const& uri_in)
{
  return os << uri_in.parts();
}
