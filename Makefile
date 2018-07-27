USES := libglog libidn2

LIBS := uri
uri_STEMS := uri

CXXFLAGS += -IPEGTL/include
LDLIBS += \
	-lfmt \
	-lunistring

TESTS := uri-test

# safty_flags := # nada
# visibility_flags := # nada
# lto_flags := # nada

include MKUltra/rules
