#include <ares.h>
#include <assert.h>
#include <bare.h>
#include <js.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <utf.h>
#include <uv.h>

#ifndef offset_of
#define offset_of(type, member) ((intptr_t) ((char *) (&(((type *) (0))->member))))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type *) ((char *) (ptr) - offset_of(type, member)))
#endif

typedef struct {
  uv_getaddrinfo_t handle;

  js_env_t *env;
  js_ref_t *ctx;
  js_ref_t *cb;

  bool all;
  bool exiting;

  js_deferred_teardown_t *teardown;
} bare_dns_lookup_t;

typedef struct {
  ares_channel channel;
  ares_socket_t socket;

  uv_poll_t poll;

  js_env_t *env;
  js_ref_t *ctx;
  js_ref_t *cb;
} bare_dns_resolve_t;

static void
bare_dns__on_lookup(uv_getaddrinfo_t *handle, int status, struct addrinfo *res) {
  int err;

  bare_dns_lookup_t *req = (bare_dns_lookup_t *) handle;

  js_env_t *env = req->env;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_value_t *ctx;
  err = js_get_reference_value(env, req->ctx, &ctx);
  assert(err == 0);

  js_value_t *cb;
  err = js_get_reference_value(env, req->cb, &cb);
  assert(err == 0);

  err = js_delete_reference(env, req->cb);
  assert(err == 0);

  err = js_delete_reference(env, req->ctx);
  assert(err == 0);

  js_value_t *args[2];

  if (status < 0) {
    js_value_t *code;
    err = js_create_string_utf8(env, (utf8_t *) uv_err_name(status), -1, &code);
    assert(err == 0);

    js_value_t *message;
    err = js_create_string_utf8(env, (utf8_t *) uv_strerror(status), -1, &message);
    assert(err == 0);

    err = js_create_error(env, code, message, &args[0]);
    assert(err == 0);

    err = js_get_null(env, &args[1]);
    assert(err == 0);
  } else {
    err = js_get_null(env, &args[0]);
    assert(err == 0);

    js_value_t *result;
    err = js_create_array(env, &result);
    assert(err == 0);

    uint32_t i = 0;

    for (struct addrinfo *next = res; next != NULL; next = next->ai_next) {
      assert(next->ai_socktype == SOCK_STREAM);

      int family;

      char ip[INET6_ADDRSTRLEN];

      if (next->ai_family == AF_INET) {
        family = 4;
        err = uv_ip4_name((struct sockaddr_in *) next->ai_addr, ip, sizeof(ip));
      } else if (next->ai_family == AF_INET6) {
        family = 6;
        err = uv_ip6_name((struct sockaddr_in6 *) next->ai_addr, ip, sizeof(ip));
      } else {
        continue;
      }

      assert(err == 0);

      js_value_t *address;
      err = js_create_object(env, &address);
      assert(err == 0);

      err = js_set_element(env, result, i++, address);
      assert(err == 0);

      js_value_t *value;

      err = js_create_string_utf8(env, (utf8_t *) ip, -1, &value);
      assert(err == 0);

      err = js_set_named_property(env, address, "address", value);
      assert(err == 0);

      err = js_create_uint32(env, family, &value);
      assert(err == 0);

      err = js_set_named_property(env, address, "family", value);
      assert(err == 0);

      if (!req->all) break;
    }

    if (i > 0) args[1] = result;
    else {
      js_value_t *code;
      err = js_create_string_utf8(env, (utf8_t *) uv_err_name(UV_EAI_NODATA), -1, &code);
      assert(err == 0);

      js_value_t *message;
      err = js_create_string_utf8(env, (utf8_t *) uv_strerror(UV_EAI_NODATA), -1, &message);
      assert(err == 0);

      err = js_create_error(env, code, message, &args[0]);
      assert(err == 0);

      err = js_get_null(env, &args[1]);
      assert(err == 0);
    }
  }

  uv_freeaddrinfo(res);

  if (!req->exiting) js_call_function(req->env, ctx, cb, 2, args, NULL);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);

  err = js_finish_deferred_teardown_callback(req->teardown);
  assert(err == 0);
}

static void
bare_dns__on_teardown(js_deferred_teardown_t *handle, void *data) {
  bare_dns_lookup_t *req = (bare_dns_lookup_t *) data;

  req->exiting = true;

  uv_cancel((uv_req_t *) &req->handle);
}

static js_value_t *
bare_dns_lookup(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 5;
  js_value_t *argv[5];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 5);

  size_t len;
  err = js_get_value_string_utf8(env, argv[0], NULL, 0, &len);
  assert(err == 0);

  len += 1 /* NULL */;

  utf8_t *hostname = malloc(len);
  err = js_get_value_string_utf8(env, argv[0], hostname, len, NULL);
  assert(err == 0);

  uint32_t family;
  err = js_get_value_uint32(env, argv[1], &family);
  assert(err == 0);

  bool all;
  err = js_get_value_bool(env, argv[2], &all);
  assert(err == 0);

  struct addrinfo hints = {
    .ai_family = family == 4
                   ? AF_INET
                 : family == 6 ? AF_INET6
                               : AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
    .ai_flags = 0,
  };

  js_value_t *handle;

  bare_dns_lookup_t *req;
  err = js_create_arraybuffer(env, sizeof(bare_dns_lookup_t), (void **) &req, &handle);
  assert(err == 0);

  req->env = env;
  req->all = all;
  req->exiting = false;

  err = js_create_reference(env, argv[3], 1, &req->ctx);
  assert(err == 0);

  err = js_create_reference(env, argv[4], 1, &req->cb);
  assert(err == 0);

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_getaddrinfo(loop, &req->handle, bare_dns__on_lookup, (const char *) hostname, NULL, &hints);

  free(hostname);

  if (err < 0) {
    js_throw_error(env, uv_err_name(err), uv_strerror(err));
    return NULL;
  }

  err = js_add_deferred_teardown_callback(env, bare_dns__on_teardown, (void *) req, &req->teardown);
  assert(err == 0);

  return handle;
}

void
bare_dns__on_resolve_txt(void *data, ares_status_t status, size_t timeouts, const ares_dns_record_t *dnsrec) {
  int err;

  bare_dns_resolve_t *req = (bare_dns_resolve_t *) data;

  js_env_t *env = req->env;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_value_t *ctx;
  err = js_get_reference_value(env, req->ctx, &ctx);
  assert(err == 0);

  js_value_t *cb;
  err = js_get_reference_value(env, req->cb, &cb);
  assert(err == 0);

  err = js_delete_reference(env, req->cb);
  assert(err == 0);

  err = js_delete_reference(env, req->ctx);
  assert(err == 0);

  js_value_t *args[2];

  if (status == ARES_SUCCESS) {
    unsigned char *buf;
    size_t len = 0;

    status = ares_dns_write(dnsrec, &buf, &len);
    assert(status == ARES_SUCCESS);

    struct ares_txt_ext *reply;

    status = ares_parse_txt_reply_ext(buf, len, &reply);
    assert(status == ARES_SUCCESS);

    err = js_get_null(env, &args[0]);
    assert(err == 0);

    js_value_t *result;
    err = js_create_array(env, &result);
    assert(err == 0);

    uint32_t i = 0;

    for (struct ares_txt_ext *next = reply; next != NULL; next = next->next) {
      js_value_t *chunk;
      err = js_create_string_utf8(env, (utf8_t *) next->txt, next->length, &chunk);
      assert(err == 0);

      if (next->record_start) {
        js_value_t *record;
        err = js_create_array(env, &record);
        assert(err == 0);

        err = js_set_element(env, record, 0, chunk);
        assert(err == 0);

        err = js_set_element(env, result, i++, record);
        assert(err == 0);
      } else {
        js_value_t *record;
        err = js_get_element(env, result, i, &record);
        assert(err == 0);

        uint32_t len;
        err = js_get_array_length(env, record, &len);
        assert(err == 0);

        err = js_set_element(env, record, len, chunk);
        assert(err == 0);
      }
    }

    args[1] = result;

    ares_free_data(reply);
  } else {
    js_value_t *message;
    err = js_create_string_utf8(env, (utf8_t *) ares_strerror(status), -1, &message);
    assert(err == 0);

    err = js_create_error(env, NULL, message, &args[0]);
    assert(err == 0);

    err = js_get_null(env, &args[1]);
    assert(err == 0);
  }

  js_call_function(env, ctx, cb, 2, args, NULL);

  err = js_close_handle_scope(req->env, scope);
  assert(err == 0);
}

void
bare_dns__on_poll_update(uv_poll_t *poll, int status, int events) {
  assert(status == 0);

  bare_dns_resolve_t *handle = container_of(poll, bare_dns_resolve_t, poll);

  ares_process_fd(
    handle->channel,
    events & UV_READABLE ? handle->socket : ARES_SOCKET_BAD,
    events & UV_WRITABLE ? handle->socket : ARES_SOCKET_BAD
  );
}

void
bare_dns__on_socket_change(void *data, ares_socket_t socket, int read, int write) {
  int err;

  bare_dns_resolve_t *handle = (bare_dns_resolve_t *) data;

  if (read == 0 && write == 0) {
    return uv_close((uv_handle_t *) &handle->poll, NULL);
  }

  handle->socket = socket;

  uv_loop_t *loop;
  err = js_get_env_loop(handle->env, &loop);
  assert(err == 0);

  err = uv_poll_init_socket(loop, &handle->poll, socket);
  assert(err == 0);

  int events = (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0);
  err = uv_poll_start(&handle->poll, events, bare_dns__on_poll_update);
  assert(err == 0);
}

static js_value_t *
bare_dns_resolve_txt(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 3;
  js_value_t *argv[3];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 3);

  size_t len;
  err = js_get_value_string_utf8(env, argv[0], NULL, 0, &len);
  assert(err == 0);

  len += 1 /* NULL */;

  utf8_t *hostname = malloc(len);
  err = js_get_value_string_utf8(env, argv[0], hostname, len, NULL);
  assert(err == 0);

  js_value_t *handle;

  bare_dns_resolve_t *req;
  err = js_create_arraybuffer(env, sizeof(bare_dns_resolve_t), (void **) &req, &handle);
  assert(err == 0);

  req->env = env;

  err = js_create_reference(env, argv[1], 1, &req->cb);
  assert(err == 0);

  err = js_create_reference(env, argv[2], 1, &req->ctx);
  assert(err == 0);

  err = ares_library_init(ARES_LIB_INIT_ALL);
  assert(err == ARES_SUCCESS);

  struct ares_options opts;
  opts.sock_state_cb = bare_dns__on_socket_change;
  opts.sock_state_cb_data = req;

  err = ares_init_options(&req->channel, &opts, ARES_OPT_SOCK_STATE_CB);
  assert(err == ARES_SUCCESS);

  ares_status_t status;
  status = ares_query_dnsrec(req->channel, (char *) hostname, ARES_CLASS_IN, ARES_REC_TYPE_TXT, bare_dns__on_resolve_txt, req, NULL);
  assert(err == ARES_SUCCESS);

  free(hostname);

  return NULL;
}

static js_value_t *
bare_dns_exports(js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

  V("lookup", bare_dns_lookup)
  V("resolveTxt", bare_dns_resolve_txt)
#undef V

  return exports;
}

BARE_MODULE(bare_dns, bare_dns_exports)
