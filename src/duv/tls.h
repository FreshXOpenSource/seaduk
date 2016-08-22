#ifndef tls_H
#define tls_H

#include "duv.h"
#include "../evt_tls.h"

duk_ret_t duv_new_tls(duk_context *ctx);
duk_ret_t duv_tls_open(duk_context *ctx);
duk_ret_t duv_tls_nodelay(duk_context *ctx);
duk_ret_t duv_tls_keepalive(duk_context *ctx);
duk_ret_t duv_tls_simultaneous_accepts(duk_context *ctx);
duk_ret_t duv_tls_bind(duk_context *ctx);
duk_ret_t duv_tls_getpeername(duk_context *ctx);
duk_ret_t duv_tls_getsockname(duk_context *ctx);
duk_ret_t duv_tls_connect(duk_context *ctx);

#endif
