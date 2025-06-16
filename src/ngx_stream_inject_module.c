/*
 * ngx_stream_inject_module.c
 * Copyright (c) 2025 Brogan Scott Houston McIntyre (github.com/TechTank)
 *
 * This file is part of ngx_stream_inject_module.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to use,
 * copy, and modify the Software for personal, non-commercial, and educational purposes.
 *
 * Commercial use, including but not limited to integration into proprietary software,
 * Software-as-a-Service (SaaS) platforms, or services offered to third parties,
 * requires a commercial license.
 *
 * https://github.com/TechTank
 *
 * ========== ========== ========== ========== ==========
 *
 * Inject a custom string immediately after the upstream TCP
 * connection is established. Can be enabled globally or per-server,
 * with a configurable maximum inject size.
 *
 * Example:
 *
 *   stream {
 *       inject_enable       on;
 *       inject_max_length   1024;
 *
 *       server {
 *           listen          12345;
 *           proxy_pass      backend;
 *
 *           inject_enable   off;
 *           inject_string   "Hello world!\r\n";
 *       }
 *   }
 *
 * Build as part of your OpenResty or nginx-plus stream modules.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_socket.h>
#include <ngx_stream.h>
#include <ngx_stream_script.h>
#include <ngx_stream_upstream.h>

#define NGX_INJECT_MAX_DEFER  100

#include "ngx_stream_inject_module.h"

/* forward declarations */
static ngx_int_t  ngx_stream_inject_preconf(ngx_conf_t *cf);
static ngx_int_t  ngx_stream_inject_init(ngx_conf_t *cf);
static ngx_int_t  ngx_stream_inject_content(ngx_stream_session_t *s);
static void       ngx_stream_inject_content_wrapper(ngx_stream_session_t *s);
static void       ngx_stream_inject_on_upstream_connected(ngx_event_t *ev);
static void       ngx_stream_inject_cleanup(void *data);

static void *     ngx_stream_inject_create_main_conf(ngx_conf_t *cf);
static char *     ngx_stream_inject_init_main_conf(ngx_conf_t *cf, void *conf);
static void *     ngx_stream_inject_create_srv_conf(ngx_conf_t *cf);
static char *     ngx_stream_inject_merge_srv_conf(ngx_conf_t *cf,
                                                   void *parent,
                                                   void *child);

/* module directives */
static ngx_command_t  ngx_stream_inject_commands[] = {
    {
        ngx_string("inject_enable"),
        NGX_STREAM_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_STREAM_MAIN_CONF_OFFSET,
        offsetof(ngx_stream_inject_main_conf_t, enable),
        NULL
    },
    {
        ngx_string("inject_enable"),
        NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_stream_inject_srv_conf_t, enable),
        NULL
    },
    {
        ngx_string("inject_max_length"),
        NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_STREAM_MAIN_CONF_OFFSET,
        offsetof(ngx_stream_inject_main_conf_t, max_inject_len),
        NULL
    },
    {
        ngx_string("inject_max_length"),
        NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_stream_inject_srv_conf_t, max_inject_len),
        NULL
    },
    {
        ngx_string("inject_max_defer"),
        NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_STREAM_MAIN_CONF_OFFSET,
        offsetof(ngx_stream_inject_main_conf_t, max_defer),
        NULL
    },
    {
        ngx_string("inject_string"),
        NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_stream_inject_set_string,
        NGX_STREAM_SRV_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

/* module context */
static ngx_stream_module_t  ngx_stream_inject_module_ctx = {
    ngx_stream_inject_preconf,
    ngx_stream_inject_init,

    ngx_stream_inject_create_main_conf,
    ngx_stream_inject_init_main_conf,
    ngx_stream_inject_create_srv_conf,
    ngx_stream_inject_merge_srv_conf
};

ngx_module_t  ngx_stream_inject_module = {
    NGX_MODULE_V1,
    &ngx_stream_inject_module_ctx,
    ngx_stream_inject_commands,
    NGX_STREAM_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/*
 * ngx_stream_inject_create_main_conf()
 *    allocate main configuration, unset values
 */
static void *
ngx_stream_inject_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_inject_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable         = NGX_CONF_UNSET;
    conf->max_inject_len = NGX_CONF_UNSET_SIZE;
    conf->max_defer      = NGX_CONF_UNSET_UINT;

    return conf;
}

/*
 * ngx_stream_inject_init_main_conf()
 *    fill defaults and validate max_inject_len, max_defer
 */
static char *
ngx_stream_inject_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_stream_inject_main_conf_t  *mcf = conf;

    ngx_conf_init_value     (mcf->enable,          1);
    ngx_conf_init_size_value(mcf->max_inject_len,  1024);
    ngx_conf_init_uint_value(mcf->max_defer,       NGX_INJECT_MAX_DEFER);

    if (mcf->max_inject_len == 0 || mcf->max_inject_len > 1024 * 1024) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "inject_max_length must be between 1 and 1MB");
        return NGX_CONF_ERROR;
    }

    if (mcf->max_defer == 0 || mcf->max_defer > 1000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "inject_max_defer must be between 1 and 1000");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * ngx_stream_inject_create_srv_conf()
 *    allocate per-server config, unset fields
 */
static void *
ngx_stream_inject_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_inject_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->original_handler = NULL;
    conf->has_variables    = 0;
    conf->enable           = NGX_CONF_UNSET;
    conf->max_inject_len   = NGX_CONF_UNSET_SIZE;

    return conf;
}

/*
 * ngx_stream_inject_merge_srv_conf()
 *    merge parent into child, inherit inject value
 */
static char *
ngx_stream_inject_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_inject_srv_conf_t  *prev = parent;
    ngx_stream_inject_srv_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_size_value(conf->max_inject_len,
                              prev->max_inject_len, 1024);

    if (conf->inject.value.data == NULL) {
        conf->inject        = prev->inject;
        conf->has_variables = prev->has_variables;
    }

    return NGX_CONF_OK;
}

/*
 * ngx_stream_inject_set_string()
 *    parse inject_string; compile complex value if needed
 */
char *
ngx_stream_inject_set_string(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_inject_srv_conf_t       *iscf = conf;
    ngx_str_t                          *value = cf->args->elts;
    ngx_stream_compile_complex_value_t  ccv;

    if (iscf->inject.value.data) {
        ngx_pfree(cf->pool, iscf->inject.value.data);
        iscf->inject.value.data = NULL;
        iscf->inject.value.len  = 0;
    }

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid number of arguments in \"inject_string\"");
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "inject_string cannot be empty");
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_script_variables_count(&value[1]) > 0) {
        ngx_memzero(&ccv, sizeof(ccv));
        ccv.cf            = cf;
        ccv.value         = &value[1];
        ccv.complex_value = &iscf->inject;

        if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        iscf->has_variables = 1;
    }
    else {
        iscf->inject.value.data = ngx_pnalloc(cf->pool, value[1].len);
        if (iscf->inject.value.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(iscf->inject.value.data, value[1].data, value[1].len);
        iscf->inject.value.len = value[1].len;
        iscf->has_variables = 0;
    }

    return NGX_CONF_OK;
}

/*
 * ngx_stream_inject_content()
 *    stream content‐phase handler:
 *      - invoke original handler or proxy
 *      - defer until upstream is connected
 *      - install upstream write hook
 */
static ngx_int_t
ngx_stream_inject_content(ngx_stream_session_t *s)
{
    ngx_stream_inject_main_conf_t  *mcf;
    ngx_stream_inject_srv_conf_t   *iscf;
    ngx_stream_inject_ctx_t        *ctx;
    ngx_connection_t               *up;

    if (s->connection->destroyed) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: session destroyed, aborting");
        return NGX_DONE;
    }

    mcf = ngx_stream_get_module_main_conf(s, ngx_stream_inject_module);
    iscf = ngx_stream_get_module_srv_conf(s, ngx_stream_inject_module);

    if (iscf->original_handler) {
        iscf->original_handler(s);
    }
    else {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "inject: no original handler; falling back to proxy");

        ngx_stream_core_srv_conf_t  *cscf;
        cscf = ngx_stream_get_module_srv_conf(s,
                                              ngx_stream_core_module);

        if (cscf->handler) {
            cscf->handler(s);
        }
        else {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "inject: no proxy handler; skipping injection");
            return NGX_OK;
        }
    }

    if (s->connection->ssl && !s->connection->ssl->handshaked) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: SSL handshake incomplete; deferring");
        ngx_post_event(s->connection->write, &ngx_posted_events);
        return NGX_OK;
    }

    if (s->upstream == NULL
        || s->upstream->peer.connection == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: upstream not ready; deferring");
        ngx_post_event(s->connection->write, &ngx_posted_events);
        return NGX_OK;
    }

    up = s->upstream->peer.connection;
    if (!up->write->active) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: upstream connection not active; deferring");
        ngx_post_event(up->write, &ngx_posted_events);
        return NGX_OK;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_inject_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(*ctx));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "inject: context allocation failed");
            return NGX_ERROR;
        }
        ctx->buffer.data          = NULL;
        ctx->buffer.len           = 0;
        ctx->sent                 = 0;
        ctx->injecting            = 0;
        ctx->defer_count          = 0;
        ctx->saved_write_handler  = NULL;
        ctx->hooked               = 0;
        ctx->pool                 = s->connection->pool;
        ctx->session              = s;
        ngx_stream_set_ctx(s, ctx, ngx_stream_inject_module);

        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(s->connection->pool, 0);
        if (cln == NULL) {
            ngx_pfree(s->connection->pool, ctx);
            return NGX_ERROR;
        }
        cln->handler = ngx_stream_inject_cleanup;
        cln->data = ctx;
    }

    if (up->write->error || up->read->error) {
        if (ctx->defer_count++ > mcf->max_defer) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "inject: upstream connection timeout");
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return NGX_DONE;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: upstream not ready (count=%ui)", ctx->defer_count);
        ngx_post_event(up->write, &ngx_posted_events);
        return NGX_OK;
    }

    if (iscf->enable
        && iscf->inject.value.len > 0
        && !ctx->injecting
        && !ctx->hooked)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: installing upstream hook");
        ctx->saved_write_handler = up->write->handler;
        up->write->handler       = ngx_stream_inject_on_upstream_connected;
        ctx->hooked              = 1;
        ngx_post_event(up->write, &ngx_posted_events);
    }

    ngx_handle_write_event(up->write, 0);
    return NGX_OK;
}

/*
 * ngx_stream_inject_content_wrapper()
 *    call content handler and ignore its return code
 */
static void
ngx_stream_inject_content_wrapper(ngx_stream_session_t *s)
{
    (void)ngx_stream_inject_content(s); /* ignore return value */
}

/*
 * ngx_stream_inject_on_upstream_connected()
 *    upstream write hook:
 *      - restore original write handler
 *      - evaluate and send inject buffer
 */
void
ngx_stream_inject_on_upstream_connected(ngx_event_t *ev)
{
    ngx_connection_t *up = ev->data;
    if (up->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, up->log, 0,
            "inject: upstream connection has no session");
        return;
    }

    ngx_stream_session_t *s = up->data;
    if (s->connection->destroyed) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: session destroyed, aborting");
        return;
    }

    ngx_stream_inject_srv_conf_t  *iscf;
    ngx_stream_inject_ctx_t       *ctx;
    ngx_str_t                      inject;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_inject_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "inject: missing context");
        return;
    }

    if (ctx->hooked && ctx->saved_write_handler) {
        up->write->handler = ctx->saved_write_handler;
        ctx->hooked        = 0;
    } else if (ctx->hooked) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: already hooked, skipping");
        return;
    }

    iscf = ngx_stream_get_module_srv_conf(s, ngx_stream_inject_module);

    if (iscf->enable == 0 || iscf->inject.value.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: disabled or empty string");
        ngx_handle_write_event(up->write, 0);
        return;
    }

    if (!ctx->injecting) {
        if (up->ssl && !up->ssl->handshaked) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "inject: upstream SSL handshake incomplete; deferring");
            ngx_post_event(up->write, &ngx_posted_events);
            return;
        }

        if (ctx->buffer.data && ctx->buffer.data != iscf->inject.value.data) {
            ngx_pfree(s->connection->pool, ctx->buffer.data);
            ctx->buffer.data = NULL;
            ctx->buffer.len = 0;
        }

        if (iscf->has_variables) {
            if (ngx_stream_complex_value(s, &iscf->inject, &inject) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "inject: complex value evaluation failed");
                return;
            }
        } else {
            inject = iscf->inject.value;
        }

        if (inject.len == 0 || inject.len > iscf->max_inject_len) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                "inject: invalid inject length %z (max: %z, min: 1)",
                inject.len, iscf->max_inject_len);
            return;
        }

        ctx->buffer    = inject;
        ctx->sent      = 0;
        ctx->injecting = 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
        "inject: sending %V", &ctx->buffer);

    while (ctx->sent < ctx->buffer.len) {
        ssize_t n = up->send(up,
            ctx->buffer.data + ctx->sent,
            ctx->buffer.len - ctx->sent);

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "inject: sent %z/%z bytes", n, ctx->buffer.len);

        if (n == NGX_AGAIN || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "inject: EAGAIN; retrying");
            ngx_handle_write_event(up->write, 0);
            return;
        }

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "inject: send error");
            ctx->injecting = 0;
            return;
        }

        if (n > 0) {
            ctx->sent += n;
            if (ctx->sent < ctx->buffer.len) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                    "inject: partial send, retrying");
                ngx_handle_write_event(up->write, 0);
                return;
            }
        }
    }

    ctx->injecting = 0;
    ngx_handle_write_event(up->write, 0);
}

/*
 * ngx_stream_inject_preconf()
 *     insert a placeholder handler into the stream content phase
 *     to allow hooking into the post-configuration phase
 */
static ngx_int_t
ngx_stream_inject_preconf(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_phase_t            *phase;
    ngx_stream_phase_handler_t    *ph;

    cmcf = ngx_stream_conf_get_module_main_conf(cf,
                                               ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    phase = &cmcf->phases[NGX_STREAM_CONTENT_PHASE];

    if (phase->handlers.elts == NULL) {
        if (ngx_array_init(&phase->handlers, cf->pool, 4,
                           sizeof(ngx_stream_phase_handler_t)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ph = ngx_array_push(&phase->handlers);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    ph->checker = ngx_stream_core_generic_phase;
    ph->handler = ngx_stream_inject_content;
    ph->next    = NGX_STREAM_CONTENT_PHASE;

    return NGX_OK;
}

/*
 * ngx_stream_inject_init()
 *     replace each server’s content handler with our wrapper
 */
static ngx_int_t
ngx_stream_inject_init(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_core_srv_conf_t  **cscfp;
    ngx_uint_t                    i;

    cmcf = ngx_stream_conf_get_module_main_conf(cf,
                                               ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    cscfp = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        ngx_stream_core_srv_conf_t   *cscf = cscfp[i];
        ngx_stream_inject_srv_conf_t *iscf;

        iscf = ngx_stream_conf_get_module_srv_conf(cscf,
                                                   ngx_stream_inject_module);

        if (iscf == NULL) {
            continue;
        }

        if (cscf->handler == ngx_stream_inject_content_wrapper) {
            continue;
        }

        iscf->original_handler = cscf->handler;
        cscf->handler          = ngx_stream_inject_content_wrapper;
    }

    return NGX_OK;
}

/*
 * ngx_stream_inject_cleanup()
 *    free dynamic inject buffer on session cleanup
 */
static void __attribute__((used))
ngx_stream_inject_cleanup(void *data)
{
    ngx_stream_inject_ctx_t *ctx = data;
    ngx_stream_inject_srv_conf_t *iscf;
    if (ctx->buffer.data) {
        iscf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_inject_module);
        if (iscf && ctx->buffer.data != iscf->inject.value.data) {
            ngx_pfree(ctx->pool, ctx->buffer.data);
        }
    }
}