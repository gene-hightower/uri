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
  std::optional<std::string_view> scheme;
  std::optional<std::string_view> authority; // further broken down into:
  std::optional<std::string_view> userinfo;  //  from authority
  std::optional<std::string_view> host;      //  from authority
  std::optional<std::string_view> port;      //  from authority
  std::optional<std::string_view> path;
  std::optional<std::string_view> query;
  std::optional<std::string_view> fragment;
};

DLL_PUBLIC bool parse_generic(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_relative_ref(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_reference(std::string_view uri, components& comp);
DLL_PUBLIC bool parse_absolute(std::string_view uri, components& comp);

DLL_PUBLIC std::string to_string(components const&);

DLL_PUBLIC std::string normalize(components);

enum class form : bool {
  unnormalized,
  normalized,
};

class uri : boost::operators<uri> {
public:
  uri() {}

  // Base classes add nothing but new ctors(), so skip the vtable.
  // virtual ~uri() {}

  // copy
  uri(uri const&);
  uri& operator=(uri const&);

  // move
  uri(uri&&);
  uri& operator=(uri&&);

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

  std::string const& string() const { return uri_; }
  std::string_view string_view() const { return string(); }

  bool empty() const { return string_view().empty(); }

  bool operator<(uri const& rhs) const;
  bool operator==(uri const& rhs) const;

protected:
  std::string uri_;
  components parts_; // All the string_views in parts_ point into uri_.
  form form_{form::unnormalized};
};

// Derived types add only ctor()s that use different parsers.

class generic : public uri {
public:
  generic(std::string uri_in, bool norm = false);
  generic(components const& uri_in, bool norm = false);
};

class absolute : public uri {
public:
  absolute(std::string uri_in, bool norm = false);
  absolute(components const& uri_in, bool norm = false);
};

class reference : public uri {
public:
  reference(std::string uri_in, bool norm = false);
  reference(components const& uri_in, bool norm = false);
};

DLL_PUBLIC uri resolve_ref(absolute const& base, reference const& ref);

} // namespace uri

DLL_PUBLIC std::ostream& operator<<(std::ostream& os,
                                    uri::components const& uri);
DLL_PUBLIC std::ostream& operator<<(std::ostream& os, uri::uri const&);

#endif // URI_HPP_INCLUDED
