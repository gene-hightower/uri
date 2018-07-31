#ifndef URI_HPP_INCLUDED
#define URI_HPP_INCLUDED

#include "dll_spec.h"

#include <cctype>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace uri {

enum class error {
  // parser errors
  invalid_syntax = 1,
};

class DLL_PUBLIC syntax_error : public std::system_error {
public:
  syntax_error();
  virtual ~syntax_error() noexcept;
};

const std::error_category& category();

struct components {
  std::optional<std::string_view> scheme;
  std::optional<std::string_view> authority; // further brokwn down into:
  std::optional<std::string_view> userinfo;  //  from authority
  std::optional<std::string_view> host;      //  from authority
  std::optional<std::string_view> port;      //  from authority
  std::optional<std::string_view> path;
  std::optional<std::string_view> query;
  std::optional<std::string_view> fragment;

  bool operator==(components const& rhs) const
  {
    return (scheme == rhs.scheme) && (authority == rhs.authority)
           && (userinfo == rhs.userinfo) && (host == rhs.host)
           && (port == rhs.port) && (path == rhs.path) && (query == rhs.query)
           && (fragment == rhs.fragment);
  }
  bool operator!=(components const& rhs) const { return !(*this == rhs); }
};

DLL_PUBLIC bool parse_generic(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_relative_ref(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_reference(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_absolute(std::string_view uri, components& comp);

DLL_PUBLIC std::string to_string(components const&);

DLL_PUBLIC std::string normalize(components);

class uri {
public:
  uri() = default;

  explicit uri(std::string_view uri_in)
    : uri_(uri_in)
  {
    if (!parse_generic(uri_, parts_)) {
      throw syntax_error();
    }
  }

  explicit uri(components const& uri_in)
    : uri(to_string(uri_in))
  {
  }

  // clang-format off
  auto scheme()    const { return parts_.scheme; }
  auto authority() const { return parts_.authority; }
  auto userinfo()  const { return parts_.userinfo; }
  auto host()      const { return parts_.host; }
  auto port()      const { return parts_.port; }
  auto path()      const { return parts_.path; }
  auto query()     const { return parts_.query; }
  auto fragment()  const { return parts_.fragment; }
  // clang-format on

  components const& parts() const { return parts_; }

  std::string_view string() const { return uri_; }

  bool empty() const
  {
    return !(parts_.scheme || parts_.authority || parts_.userinfo || parts_.host
             || parts_.port || parts_.path || parts_.query || parts_.fragment);
  }

private:
  std::string uri_;
  components parts_;
};

DLL_PUBLIC std::string to_string(uri const&);

} // namespace uri

DLL_PUBLIC std::ostream& operator<<(std::ostream& os,
                                    uri::components const& uri);
DLL_PUBLIC std::ostream& operator<<(std::ostream& os, uri::uri const&);

#endif // URI_HPP_INCLUDED
