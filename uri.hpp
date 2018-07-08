#ifndef URI_HPP_INCLUDED
#define URI_HPP_INCLUDED

#include <iostream>
#include <string>
#include <string_view>

namespace uri {

enum class error {
  // parser errors
  invalid_syntax = 1,
};

class syntax_error : public std::system_error {
public:
  syntax_error();
  virtual ~syntax_error() noexcept;
};

const std::error_category& category();

struct components {
  std::string_view scheme;
  std::string_view authority; // further brokwn down into:
  std::string_view userinfo;  //  from authority
  std::string_view host;      //  from authority
  std::string_view port;      //  from authority
  std::string_view path;
  std::string_view query;
  std::string_view fragment;
};

std::string to_string(uri::components const& uri);

bool parse_generic(std::string_view uri, components& comp);
bool parse_relative_ref(std::string_view uri, components& comp);
bool parse_reference(std::string_view uri, components& comp);
bool parse_absolute(std::string_view uri, components& comp);

class generic {
public:
  generic() = default;

  explicit generic(components const& uri)
    : uri_(to_string(uri))
  {
    if (!parse_generic(uri_, parts_)) {
      throw syntax_error();
    }
  }

  explicit generic(std::string_view uri)
    : uri_(uri)
  {
    if (!parse_generic(uri_, parts_)) {
      throw syntax_error();
    }
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

private:
  std::string uri_;
  components parts_;
};

std::string to_string(uri::generic const& uri);

} // namespace uri

std::ostream& operator<<(std::ostream& os, uri::components const& uri);
std::ostream& operator<<(std::ostream& os, uri::generic const& uri);

#endif // URI_HPP_INCLUDED
