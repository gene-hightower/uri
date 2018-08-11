#ifndef URI_HPP_INCLUDED
#define URI_HPP_INCLUDED

#include "dll_spec.h"

#include <cctype>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include <boost/operators.hpp>

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
  std::optional<std::string> scheme;
  std::optional<std::string> authority; // further brokwn down into:
  std::optional<std::string> userinfo;  //  from authority
  std::optional<std::string> host;      //  from authority
  std::optional<std::string> port;      //  from authority
  std::optional<std::string> path;
  std::optional<std::string> query;
  std::optional<std::string> fragment;
};

DLL_PUBLIC bool parse_generic(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_relative_ref(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_reference(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_absolute(std::string_view uri, components& comp);

DLL_PUBLIC std::string to_string(components const&);

DLL_PUBLIC std::string normalize(components);

class uri : boost::operators<uri> {
public:

  // clang-format off
  auto const& scheme()    const { return parts_.scheme; }
  auto const& authority() const { return parts_.authority; }
  auto const& userinfo()  const { return parts_.userinfo; }
  auto const& host()      const { return parts_.host; }
  auto const& port()      const { return parts_.port; }
  auto const& path()      const { return parts_.path; }
  auto const& query()     const { return parts_.query; }
  auto const& fragment()  const { return parts_.fragment; }
  // clang-format on

  components const& parts() const { return parts_; }

  std::string_view string() const { return uri_; }

  bool empty() const { return string().empty(); }

  bool operator<(uri const& rhs) const { return uri_ < rhs.uri_; }
  bool operator==(uri const& rhs) const { return uri_ == rhs.uri_; }

protected:
  std::string uri_;
  components parts_;
};

class generic : public uri {
public:
  explicit generic(std::string uri_in)
  {
    uri_ = uri_in;
    if (!parse_generic(uri_, parts_)) {
      throw syntax_error();
    }
  }

  explicit generic(components const& uri_in)
    : generic(to_string(uri_in))
  {
  }
};

class absolute : public uri {
public:
  explicit absolute(std::string uri_in)
  {
    uri_ = uri_in;
    if (!parse_absolute(uri_, parts_)) {
      throw syntax_error();
    }
  }

  explicit absolute(components const& uri_in)
    : absolute(to_string(uri_in))
  {
  }
};

class reference : public uri {
public:
  explicit reference(std::string uri_in)
  {
    uri_ = uri_in;
    if (!parse_reference(uri_, parts_)) {
      throw syntax_error();
    }
  }

  explicit reference(components const& uri_in)
    : reference(to_string(uri_in))
  {
  }
};

DLL_PUBLIC std::string to_string(uri const&);

DLL_PUBLIC uri resolve_ref(absolute const& base, reference const& ref);

} // namespace uri

DLL_PUBLIC std::ostream& operator<<(std::ostream& os,
                                    uri::components const& uri);
DLL_PUBLIC std::ostream& operator<<(std::ostream& os, uri::uri const&);

#endif // URI_HPP_INCLUDED
