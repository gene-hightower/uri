USES := libglog

MKULTRA_BUILD_STATIC := yes

LIBS := uri
uri_STEMS := uri

CXXFLAGS += -IPEGTL/include

TESTS := uri-test

# safty_flags := # nada
visibility_flags := # nada
# lto_flags := # nada

include MKUltra/rules
