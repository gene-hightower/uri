USES := libglog libidn2 fmt

INCLUDES := uri.hpp dll_spec.h

LIBS := uri
uri_STEMS := uri

CXXFLAGS += -IPEGTL/include
LDLIBS += \
	-lgflags \
	-lunistring

TESTS := uri-test

safty_flags := # nada
visibility_flags := # nada
lto_flags := # nada

include MKUltra/rules
