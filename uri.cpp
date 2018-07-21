#define BUILDING_DLL
#include "uri.hpp"

#include <iostream>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
// #include <tao/pegtl/contrib/tracer.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

// clang-format off
namespace RFC3986 {

// Rules are from <https://tools.ietf.org/html/rfc3986#appendix-A>

// The order is mostly reversed here, since we need to define before use.

//     sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                   / "*" / "+" / "," / ";" / "="
struct sub_delims    : one<'!', '$', '&', '\'', '(', ')',
                           '*', '+', ',', ';', '='> {};

//     gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
struct gen_delims    : one<':', '/', '?', '#', '[', ']', '@'> {};

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

//     reserved      = gen-delims / sub-delims
struct reserved      : sor<gen_delims, sub_delims> {};

// Allowing UTF-8 in the unreserved rule isn't strictly RFC 3987 since we
// make no attempt to limit the code points to exaclude the private use
// areas.  See <https://tools.ietf.org/html/rfc3987>

//    iunreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~" / ucschar
//     unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
struct unreserved    : sor<ALPHA, DIGIT, one<'-', '.', '_', '~'>, UTF8_non_ascii> {};

//     pct-encoded   = "%" HEXDIG HEXDIG
struct pct_encoded   : seq<one<'%'>, HEXDIG, HEXDIG> {};

//     pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
struct pchar         : sor<unreserved, pct_encoded, sub_delims, one<':'>, one<'@'>> {};

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
struct path          : sor<path_abempty,
                           path_absolute,
                           path_noscheme,
                           path_rootless,
                           path_empty> {};

//     reg-name      = *( unreserved / pct-encoded / sub-delims )
struct reg_name      : star<sor<unreserved, pct_encoded, sub_delims>> {};

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
struct URI_reference_eof : sor<URI_reference, eof> {};

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
} // namespace RFC3986

// clang-format off
namespace RFC7230 {

using uri_host = RFC3986::host;

//     obs-text = %x80-FF
struct obs_text : range<'\x80', '\xFF'> {};

//     qdtext = HTAB / SP / "!" / %x23-5B ; '#'-'['
//            / %x5D-7E ; ']'-'~'
//            / obs-text
struct qdtext : sor<abnf::HTAB, abnf::SP, one<'!'>, range<'#', '['>,
                    range<']', '~'>,
                    obs_text> {};

//     quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
struct quoted_pair : seq<one<'\\'>, sor<abnf::HTAB, abnf::SP, abnf::VCHAR, obs_text>> {};

//     quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
struct quoted_string : seq<abnf::DQUOTE, star<sor<qdtext, quoted_pair>>, abnf::DQUOTE> {};

//     OWS = *( SP / HTAB )
struct OWS : star<sor<abnf::SP, abnf::HTAB>> {};

using BWS = OWS;

//   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//    "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
struct tchar : sor<one<'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'>,
                   abnf::DIGIT,
                   abnf::ALPHA> {};

//     token = 1*tchar
struct token : plus<tchar> {};

//     transfer-parameter = token BWS "=" BWS ( token / quoted-string )
struct transfer_parameter : seq<token, BWS, one<'='>, BWS, sor<token, quoted_string>> {};

} // namespace RFC7230
// clang-format on

namespace uri {
DLL_PUBLIC bool parse(std::string_view uri, components& parts)
{
  // auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  // if (tao::pegtl::parse<RFC3986::any_URI_eof, RFC3986::action>(in, parts)) {
  //   return true;
  // }
  return false;
}

DLL_PUBLIC bool parse_generic(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<RFC3986::URI_eof, RFC3986::action>(in, parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_relative_ref(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<RFC3986::relative_ref_eof, RFC3986::action>(in,
                                                                    parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_reference(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<RFC3986::URI_reference_eof, RFC3986::action>(in,
                                                                     parts)) {
    return true;
  }
  return false;
}

DLL_PUBLIC bool parse_absolute(std::string_view uri, components& parts)
{
  auto in{memory_input<>{uri.data(), uri.size(), "uri"}};
  if (tao::pegtl::parse<RFC3986::absolute_URI_eof, RFC3986::action>(in,
                                                                    parts)) {
    return true;
  }
  return false;
}

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

std::string to_string(uri::components const& uri)
{
  std::ostringstream os;
  os << uri;
  return os.str();
}

std::string to_string(uri::generic const& uri)
{
  return to_string(uri.parts());
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

  os << uri.path;

  if (!uri.query.empty()) {
    os << '?' << uri.query;
  }

  if (!uri.fragment.empty()) {
    os << '#' << uri.fragment;
  }

  return os;
}

DLL_PUBLIC std::ostream& operator<<(std::ostream& os, uri::generic const& uri)
{
  return os << uri.parts();
}
