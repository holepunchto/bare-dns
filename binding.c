#include <ares.h>
#include <assert.h>
#include <bare.h>
#include <intrusive.h>
#include <intrusive/list.h>
#include <js.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <utf.h>
#include <uv.h>

#ifndef _WIN32
#include <arpa/inet.h>
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

  intrusive_list_t tasks;
  intrusive_list_t answers;

  uv_idle_t idle;

  bool exiting;
  bool closed;

  js_env_t *env;
  js_ref_t *handle;
  js_deferred_teardown_t *teardown;
} bare_dns_resolver_t;

typedef struct {
  bare_dns_resolver_t *resolver;

  ares_socket_t socket;
  uv_poll_t poll;

  bool polling;

  intrusive_list_node_t node;
} bare_dns_resolve_task_t;

typedef struct {
  bare_dns_resolver_t *resolver;

  js_env_t *env;
  js_ref_t *ctx;
  js_ref_t *cb;

  ares_status_t status;
  ares_dns_record_t *record;

  intrusive_list_node_t node;
} bare_dns_query_t;

static uv_once_t bare_dns__init_guard = UV_ONCE_INIT;

static void
bare_dns__on_lookup(uv_getaddrinfo_t *handle, int status, struct addrinfo *res) {
  int err;

  bare_dns_lookup_t *req = (bare_dns_lookup_t *) handle;

  js_deferred_teardown_t *teardown = req->teardown;

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

  if (!req->exiting) js_call_function(env, ctx, cb, 2, args, NULL);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  err = js_finish_deferred_teardown_callback(teardown);
  assert(err == 0);
}

static void
bare_dns__on_lookup_teardown(js_deferred_teardown_t *handle, void *data) {
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
    err = js_throw_error(env, uv_err_name(err), uv_strerror(err));
    assert(err == 0);

    return NULL;
  }

  err = js_add_deferred_teardown_callback(env, bare_dns__on_lookup_teardown, (void *) req, &req->teardown);
  assert(err == 0);

  return handle;
}

static void
bare_dns__destroy_query(bare_dns_query_t *req) {
  int err;

  if (req->record != NULL) ares_dns_record_destroy(req->record);

  err = js_delete_reference(req->env, req->cb);
  assert(err == 0);

  err = js_delete_reference(req->env, req->ctx);
  assert(err == 0);

  free(req);
}

static void
bare_dns__finish_resolver(bare_dns_resolver_t *resolver) {
  int err;

  ares_destroy(resolver->channel);

  js_env_t *env = resolver->env;
  js_ref_t *handle = resolver->handle;
  js_deferred_teardown_t *teardown = resolver->teardown;

  err = js_delete_reference(env, handle);
  assert(err == 0);

  err = js_finish_deferred_teardown_callback(teardown);
  assert(err == 0);
}

static inline bool
bare_dns__resolver_is_finished(bare_dns_resolver_t *resolver) {
  return resolver->exiting && resolver->closed && intrusive_list_empty(&resolver->tasks);
}

static void
bare_dns__on_idle_close(uv_handle_t *handle) {
  bare_dns_resolver_t *resolver = (bare_dns_resolver_t *) handle->data;

  resolver->closed = true;

  if (bare_dns__resolver_is_finished(resolver)) bare_dns__finish_resolver(resolver);
}

static void
bare_dns__on_poll_close(uv_handle_t *handle) {
  uv_poll_t *poll = (uv_poll_t *) handle;

  bare_dns_resolve_task_t *task = intrusive_entry(poll, bare_dns_resolve_task_t, poll);

  bare_dns_resolver_t *resolver = task->resolver;

  intrusive_list_remove(&resolver->tasks, &task->node);

  free(task);

  if (bare_dns__resolver_is_finished(resolver)) bare_dns__finish_resolver(resolver);
}

static void
bare_dns__close_idle(bare_dns_resolver_t *resolver) {
  uv_handle_t *handle = (uv_handle_t *) &resolver->idle;

  if (!uv_is_closing(handle)) uv_close(handle, bare_dns__on_idle_close);
}

static void
bare_dns__close_resolver(bare_dns_resolver_t *resolver) {
  resolver->exiting = true;

  if (intrusive_list_empty(&resolver->answers)) bare_dns__close_idle(resolver);

  intrusive_list_for_each(next, &resolver->tasks) {
    bare_dns_resolve_task_t *task = intrusive_entry(next, bare_dns_resolve_task_t, node);

    if (!task->polling) continue;

    task->polling = false;

    uv_close((uv_handle_t *) &task->poll, bare_dns__on_poll_close);
  }
}

static void
bare_dns__abort_resolver(bare_dns_resolver_t *resolver) {
  intrusive_list_for_each(next, &resolver->answers) {
    bare_dns_query_t *req = intrusive_entry(next, bare_dns_query_t, node);

    intrusive_list_remove(&resolver->answers, &req->node);

    bare_dns__destroy_query(req);
  }

  bare_dns__close_resolver(resolver);
}

static void
bare_dns__on_poll_update(uv_poll_t *poll, int status, int events) {
  assert(status == 0);

  bare_dns_resolve_task_t *task = intrusive_entry(poll, bare_dns_resolve_task_t, poll);

  ares_process_fd(
    task->resolver->channel,
    events & UV_READABLE ? task->socket : ARES_SOCKET_BAD,
    events & UV_WRITABLE ? task->socket : ARES_SOCKET_BAD
  );
}

static void
bare_dns__on_resolver_teardown(js_deferred_teardown_t *handle, void *data) {
  bare_dns_resolver_t *resolver = (bare_dns_resolver_t *) data;

  if (resolver->exiting) return;

  bare_dns__abort_resolver(resolver);
}

static void
bare_dns__on_socket_change(void *data, ares_socket_t socket, int read, int write) {
  int err;

  bare_dns_resolver_t *resolver = (bare_dns_resolver_t *) data;

  if (resolver->exiting) return;

  bare_dns_resolve_task_t *task = NULL;

  intrusive_list_for_each(next, &resolver->tasks) {
    bare_dns_resolve_task_t *candidate = intrusive_entry(next, bare_dns_resolve_task_t, node);

    if (!candidate->polling) continue;

    if (candidate->socket == socket) {
      task = candidate;
      break;
    }
  }

  if (task == NULL) {
    if (!read && !write) return;

    task = malloc(sizeof(bare_dns_resolve_task_t));

    task->resolver = resolver;
    task->socket = socket;
    task->polling = false;

    intrusive_list_append(&resolver->tasks, &task->node);
  }

  if (read || write) {
    if (!task->polling) {
      uv_loop_t *loop;
      err = js_get_env_loop(resolver->env, &loop);
      assert(err == 0);

      err = uv_poll_init_socket(loop, &task->poll, task->socket);
      assert(err == 0);

      task->polling = true;
    }

    int events = (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0);

    err = uv_poll_start(&task->poll, events, bare_dns__on_poll_update);
    assert(err == 0);
  } else if (task->polling) {
    task->polling = false;

    uv_close((uv_handle_t *) &task->poll, bare_dns__on_poll_close);
  }
}

static js_value_t *
bare_dns_init_resolver(js_env_t *env, js_callback_info_t *info) {
  int err;

  js_value_t *handle;

  bare_dns_resolver_t *resolver;
  err = js_create_arraybuffer(env, sizeof(bare_dns_resolver_t), (void **) &resolver, &handle);
  assert(err == 0);

  intrusive_list_init(&resolver->tasks);
  intrusive_list_init(&resolver->answers);

  resolver->exiting = false;
  resolver->closed = false;

  struct ares_options opts;
  opts.sock_state_cb = bare_dns__on_socket_change;
  opts.sock_state_cb_data = resolver;

  err = ares_init_options(&resolver->channel, &opts, ARES_OPT_SOCK_STATE_CB);

  if (err != ARES_SUCCESS) {
    err = js_throw_error(env, NULL, ares_strerror(err));
    assert(err == 0);

    return NULL;
  }

  resolver->env = env;

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  assert(err == 0);

  err = uv_idle_init(loop, &resolver->idle);
  assert(err == 0);

  resolver->idle.data = (void *) resolver;

  err = js_create_reference(env, handle, 1, &resolver->handle);
  assert(err == 0);

  err = js_add_deferred_teardown_callback(env, bare_dns__on_resolver_teardown, (void *) resolver, &resolver->teardown);
  assert(err == 0);

  return handle;
}

static js_value_t *
bare_dns_destroy_resolver(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  bare_dns_resolver_t *resolver;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &resolver, NULL);
  assert(err == 0);

  if (resolver->exiting) return NULL;

  ares_cancel(resolver->channel);

  bare_dns__close_resolver(resolver);

  return NULL;
}

static void
bare_dns__key_to_name(ares_dns_rr_key_t key, char *name, size_t len) {
  const char *str = ares_dns_rr_key_tostr(key);

  size_t i = 0;

  for (; str[i] != '\0' && i + 1 < len; i++) {
    name[i] = (char) (str[i] >= 'A' && str[i] <= 'Z' ? str[i] + ('a' - 'A') : str[i]);
  }

  name[i] = '\0';
}

static void
bare_dns__value_to_js(js_env_t *env, const ares_dns_rr_t *rr, ares_dns_rr_key_t key, js_value_t **result) {
  int err;

  switch (ares_dns_rr_key_datatype(key)) {
  case ARES_DATATYPE_INADDR: {
    const struct in_addr *addr = ares_dns_rr_get_addr(rr, key);

    if (addr == NULL) goto null;

    char ip[INET6_ADDRSTRLEN];

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = *addr;

    err = uv_ip4_name(&sin, ip, sizeof(ip));
    assert(err == 0);

    err = js_create_string_utf8(env, (utf8_t *) ip, -1, result);
    assert(err == 0);
    break;
  }

  case ARES_DATATYPE_INADDR6: {
    const struct ares_in6_addr *addr = ares_dns_rr_get_addr6(rr, key);

    if (addr == NULL) goto null;

    char ip[INET6_ADDRSTRLEN];

    struct sockaddr_in6 sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    memcpy(&sin.sin6_addr, addr, sizeof(sin.sin6_addr));

    err = uv_ip6_name(&sin, ip, sizeof(ip));
    assert(err == 0);

    err = js_create_string_utf8(env, (utf8_t *) ip, -1, result);
    assert(err == 0);
    break;
  }

  case ARES_DATATYPE_U8:
    err = js_create_uint32(env, ares_dns_rr_get_u8(rr, key), result);
    assert(err == 0);
    break;

  case ARES_DATATYPE_U16:
    err = js_create_uint32(env, ares_dns_rr_get_u16(rr, key), result);
    assert(err == 0);
    break;

  case ARES_DATATYPE_U32:
    err = js_create_uint32(env, ares_dns_rr_get_u32(rr, key), result);
    assert(err == 0);
    break;

  case ARES_DATATYPE_NAME:
  case ARES_DATATYPE_STR: {
    const char *str = ares_dns_rr_get_str(rr, key);

    if (str == NULL) goto null;

    err = js_create_string_utf8(env, (utf8_t *) str, -1, result);
    assert(err == 0);
    break;
  }

  case ARES_DATATYPE_BIN:
  case ARES_DATATYPE_BINP: {
    size_t len;

    const unsigned char *bin = ares_dns_rr_get_bin(rr, key, &len);

    if (bin == NULL) goto null;

    void *data;
    err = js_create_arraybuffer(env, len, &data, result);
    assert(err == 0);

    memcpy(data, bin, len);
    break;
  }

  case ARES_DATATYPE_ABINP: {
    err = js_create_array(env, result);
    assert(err == 0);

    for (size_t i = 0, n = ares_dns_rr_get_abin_cnt(rr, key); i < n; i++) {
      size_t len;

      const unsigned char *bin = ares_dns_rr_get_abin(rr, key, i, &len);

      if (bin == NULL) continue;

      js_value_t *value;
      err = js_create_string_utf8(env, (utf8_t *) bin, len, &value);
      assert(err == 0);

      err = js_set_element(env, *result, (uint32_t) i, value);
      assert(err == 0);
    }
    break;
  }

  case ARES_DATATYPE_OPT: {
    err = js_create_array(env, result);
    assert(err == 0);

    for (size_t i = 0, n = ares_dns_rr_get_opt_cnt(rr, key); i < n; i++) {
      size_t len = 0;

      const unsigned char *val = NULL;

      unsigned short id = ares_dns_rr_get_opt(rr, key, i, &val, &len);

      js_value_t *option;
      err = js_create_object(env, &option);
      assert(err == 0);

      err = js_set_element(env, *result, (uint32_t) i, option);
      assert(err == 0);

      js_value_t *value;

      err = js_create_uint32(env, id, &value);
      assert(err == 0);

      err = js_set_named_property(env, option, "id", value);
      assert(err == 0);

      if (val == NULL) {
        err = js_get_null(env, &value);
        assert(err == 0);
      } else {
        void *data;
        err = js_create_arraybuffer(env, len, &data, &value);
        assert(err == 0);

        memcpy(data, val, len);
      }

      err = js_set_named_property(env, option, "value", value);
      assert(err == 0);
    }
    break;
  }

  default:
    goto null;
  }

  return;

null:
  err = js_get_null(env, result);
  assert(err == 0);
}

static void
bare_dns__rr_to_js(js_env_t *env, const ares_dns_rr_t *rr, js_value_t **result) {
  int err;

  err = js_create_object(env, result);
  assert(err == 0);

  ares_dns_rec_type_t type = ares_dns_rr_get_type(rr);

  js_value_t *value;

  const char *name = ares_dns_rr_get_name(rr);

  err = js_create_string_utf8(env, (utf8_t *) (name == NULL ? "" : name), -1, &value);
  assert(err == 0);

  err = js_set_named_property(env, *result, "name", value);
  assert(err == 0);

  err = js_create_string_utf8(env, (utf8_t *) ares_dns_rec_type_tostr(type), -1, &value);
  assert(err == 0);

  err = js_set_named_property(env, *result, "type", value);
  assert(err == 0);

  err = js_create_string_utf8(env, (utf8_t *) ares_dns_class_tostr(ares_dns_rr_get_class(rr)), -1, &value);
  assert(err == 0);

  err = js_set_named_property(env, *result, "class", value);
  assert(err == 0);

  err = js_create_uint32(env, ares_dns_rr_get_ttl(rr), &value);
  assert(err == 0);

  err = js_set_named_property(env, *result, "ttl", value);
  assert(err == 0);

  size_t len;

  const ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(type, &len);

  for (size_t i = 0; i < len; i++) {
    ares_dns_rr_key_t key = keys[i];

    char property[64];
    bare_dns__key_to_name(key, property, sizeof(property));

    bare_dns__value_to_js(env, rr, key, &value);

    err = js_set_named_property(env, *result, property, value);
    assert(err == 0);
  }
}

static void
bare_dns__section_to_js(js_env_t *env, const ares_dns_record_t *dnsrec, ares_dns_section_t section, js_value_t **result) {
  int err;

  err = js_create_array(env, result);
  assert(err == 0);

  for (size_t i = 0, n = ares_dns_record_rr_cnt(dnsrec, section); i < n; i++) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get_const(dnsrec, section, i);

    js_value_t *value;
    bare_dns__rr_to_js(env, rr, &value);

    err = js_set_element(env, *result, (uint32_t) i, value);
    assert(err == 0);
  }
}

static void
bare_dns__record_to_js(js_env_t *env, const ares_dns_record_t *dnsrec, js_value_t **result) {
  int err;

  err = js_create_object(env, result);
  assert(err == 0);

  js_value_t *value;

  err = js_create_uint32(env, ares_dns_record_get_rcode(dnsrec), &value);
  assert(err == 0);

  err = js_set_named_property(env, *result, "rcode", value);
  assert(err == 0);

  bare_dns__section_to_js(env, dnsrec, ARES_SECTION_ANSWER, &value);

  err = js_set_named_property(env, *result, "answers", value);
  assert(err == 0);

  bare_dns__section_to_js(env, dnsrec, ARES_SECTION_AUTHORITY, &value);

  err = js_set_named_property(env, *result, "authorities", value);
  assert(err == 0);

  bare_dns__section_to_js(env, dnsrec, ARES_SECTION_ADDITIONAL, &value);

  err = js_set_named_property(env, *result, "additionals", value);
  assert(err == 0);
}

static void
bare_dns__deliver_query(bare_dns_query_t *req) {
  int err;

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

  js_value_t *args[2];

  err = js_create_uint32(env, req->status, &args[0]);
  assert(err == 0);

  if (req->record != NULL) {
    bare_dns__record_to_js(env, req->record, &args[1]);
  } else {
    err = js_get_null(env, &args[1]);
    assert(err == 0);
  }

  js_call_function(env, ctx, cb, 2, args, NULL);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

  bare_dns__destroy_query(req);
}

static void
bare_dns__on_idle(uv_idle_t *idle) {
  bare_dns_resolver_t *resolver = (bare_dns_resolver_t *) idle->data;

  uv_idle_stop(idle);

  intrusive_list_t answers = resolver->answers;

  intrusive_list_init(&resolver->answers);

  intrusive_list_for_each(next, &answers) {
    bare_dns_query_t *req = intrusive_entry(next, bare_dns_query_t, node);

    intrusive_list_remove(&answers, &req->node);

    bare_dns__deliver_query(req);
  }

  if (resolver->exiting) bare_dns__close_idle(resolver);
}

static void
bare_dns__on_query(void *data, ares_status_t status, size_t timeouts, const ares_dns_record_t *dnsrec) {
  bare_dns_query_t *req = (bare_dns_query_t *) data;

  bare_dns_resolver_t *resolver = req->resolver;

  if (resolver->exiting) {
    bare_dns__destroy_query(req);

    return;
  }

  req->status = status;

  if (status == ARES_SUCCESS && dnsrec != NULL) {
    req->record = ares_dns_record_duplicate(dnsrec);

    if (req->record == NULL) req->status = ARES_ENOMEM;
  }

  intrusive_list_append(&resolver->answers, &req->node);

  uv_idle_start(&resolver->idle, bare_dns__on_idle);
}

static js_value_t *
bare_dns_query(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 5;
  js_value_t *argv[5];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 5);

  bare_dns_resolver_t *resolver;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &resolver, NULL);
  assert(err == 0);

  if (resolver->exiting) {
    err = js_throw_error(env, NULL, ares_strerror(ARES_EDESTRUCTION));
    assert(err == 0);

    return NULL;
  }

  size_t len;
  err = js_get_value_string_utf8(env, argv[1], NULL, 0, &len);
  assert(err == 0);

  len += 1 /* NULL */;

  utf8_t *name = malloc(len);
  err = js_get_value_string_utf8(env, argv[1], name, len, NULL);
  assert(err == 0);

  uint32_t type;
  err = js_get_value_uint32(env, argv[2], &type);
  assert(err == 0);

  bare_dns_query_t *req = malloc(sizeof(bare_dns_query_t));

  req->resolver = resolver;
  req->env = env;
  req->status = ARES_SUCCESS;
  req->record = NULL;

  err = js_create_reference(env, argv[3], 1, &req->ctx);
  assert(err == 0);

  err = js_create_reference(env, argv[4], 1, &req->cb);
  assert(err == 0);

  assert(resolver->channel != NULL);

  ares_query_dnsrec(resolver->channel, (char *) name, ARES_CLASS_IN, (ares_dns_rec_type_t) type, bare_dns__on_query, req, NULL);

  free(name);

  return NULL;
}

static js_value_t *
bare_dns_cancel(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  bare_dns_resolver_t *resolver;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &resolver, NULL);
  assert(err == 0);

  if (resolver->exiting) return NULL;

  ares_cancel(resolver->channel);

  return NULL;
}

static js_value_t *
bare_dns_get_servers(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  bare_dns_resolver_t *resolver;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &resolver, NULL);
  assert(err == 0);

  char *servers = ares_get_servers_csv(resolver->channel);

  js_value_t *result;
  err = js_create_string_utf8(env, (utf8_t *) (servers == NULL ? "" : servers), -1, &result);
  assert(err == 0);

  if (servers != NULL) ares_free_string(servers);

  return result;
}

static js_value_t *
bare_dns_set_servers(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 2;
  js_value_t *argv[2];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 2);

  bare_dns_resolver_t *resolver;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &resolver, NULL);
  assert(err == 0);

  size_t len;
  err = js_get_value_string_utf8(env, argv[1], NULL, 0, &len);
  assert(err == 0);

  len += 1 /* NULL */;

  utf8_t *servers = malloc(len);
  err = js_get_value_string_utf8(env, argv[1], servers, len, NULL);
  assert(err == 0);

  int status = ares_set_servers_csv(resolver->channel, (char *) servers);

  free(servers);

  if (status != ARES_SUCCESS) {
    err = js_throw_error(env, NULL, ares_strerror(status));
    assert(err == 0);
  }

  return NULL;
}

static js_value_t *
bare_dns_set_local_address(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 3;
  js_value_t *argv[3];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 3);

  bare_dns_resolver_t *resolver;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &resolver, NULL);
  assert(err == 0);

  for (size_t i = 1; i < 3; i++) {
    bool is_string;
    err = js_is_string(env, argv[i], &is_string);
    assert(err == 0);

    if (!is_string) continue;

    char address[INET6_ADDRSTRLEN];
    err = js_get_value_string_utf8(env, argv[i], (utf8_t *) address, sizeof(address), NULL);
    assert(err == 0);

    if (i == 1) {
      struct in_addr addr;

      if (ares_inet_pton(AF_INET, address, &addr) != 1) {
        err = js_throw_error(env, "EBADFAMILY", "Invalid IPv4 address");
        assert(err == 0);

        return NULL;
      }

      ares_set_local_ip4(resolver->channel, ntohl(addr.s_addr));
    } else {
      struct ares_in6_addr addr;

      if (ares_inet_pton(AF_INET6, address, &addr) != 1) {
        err = js_throw_error(env, "EBADFAMILY", "Invalid IPv6 address");
        assert(err == 0);

        return NULL;
      }

      ares_set_local_ip6(resolver->channel, (const unsigned char *) &addr);
    }
  }

  return NULL;
}

static js_value_t *
bare_dns_addr_to_ptr(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  char address[INET6_ADDRSTRLEN];
  err = js_get_value_string_utf8(env, argv[0], (utf8_t *) address, sizeof(address), NULL);
  assert(err == 0);

  struct ares_addr addr;

  if (ares_inet_pton(AF_INET, address, &addr.addr.addr4) == 1) {
    addr.family = AF_INET;
  } else if (ares_inet_pton(AF_INET6, address, &addr.addr.addr6) == 1) {
    addr.family = AF_INET6;
  } else {
    err = js_throw_error(env, "EBADFAMILY", "Invalid IP address");
    assert(err == 0);

    return NULL;
  }

  char *ptr = ares_dns_addr_to_ptr(&addr);

  if (ptr == NULL) {
    err = js_throw_error(env, "ENOMEM", "Out of memory");
    assert(err == 0);

    return NULL;
  }

  js_value_t *result;
  err = js_create_string_utf8(env, (utf8_t *) ptr, -1, &result);
  assert(err == 0);

  ares_free_string(ptr);

  return result;
}

static void
bare_dns__on_init(void) {
  ares_library_init(ARES_LIB_INIT_ALL);
}

static js_value_t *
bare_dns_exports(js_env_t *env, js_value_t *exports) {
  uv_once(&bare_dns__init_guard, bare_dns__on_init);

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

  V("initResolver", bare_dns_init_resolver)
  V("destroyResolver", bare_dns_destroy_resolver)
  V("query", bare_dns_query)
  V("cancel", bare_dns_cancel)
  V("getServers", bare_dns_get_servers)
  V("setServers", bare_dns_set_servers)
  V("setLocalAddress", bare_dns_set_local_address)
  V("addrToPtr", bare_dns_addr_to_ptr)
#undef V

  return exports;
}

BARE_MODULE(bare_dns, bare_dns_exports)
