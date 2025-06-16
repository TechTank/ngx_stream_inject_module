/*
 * ngx_stream_inject_module.h
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
 * This header defines the per-connection injection context used
 * to track upstream write handler overrides, injection state,
 * and configuration structures for ngx_stream_inject_module.
 */

#ifndef _NGX_STREAM_INJECT_MODULE_H_
#define _NGX_STREAM_INJECT_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_script.h>

extern ngx_module_t  ngx_stream_inject_module;

/* main-level configuration */
typedef struct {
    ngx_flag_t  enable;
    size_t      max_inject_len;
    ngx_uint_t  max_defer;
} ngx_stream_inject_main_conf_t;

/* per-server configuration */
typedef struct {
    ngx_flag_t                     enable;
    size_t                         max_inject_len;
    ngx_stream_complex_value_t     inject;
    ngx_flag_t                     has_variables;
    ngx_stream_content_handler_pt  original_handler;  /* real preread handler */
} ngx_stream_inject_srv_conf_t;

/* per-connection context */
typedef struct {
    ngx_str_t             buffer;              /* string we're sending */
    size_t                sent;                /* bytes already sent */
    ngx_flag_t            injecting;           /* mid-transfer flag */
    ngx_uint_t            defer_count;         /* connect poll loops */
    ngx_event_handler_pt  saved_write_handler; /* original write callback */
    ngx_flag_t            hooked;              /* hook installed flag */
    ngx_pool_t           *pool;                /* pool for memory allocation */
    ngx_stream_session_t *session;             /* session pointer */
} ngx_stream_inject_ctx_t;

/* public API */
char *ngx_stream_inject_set_string(ngx_conf_t *cf,
                                   ngx_command_t *cmd,
                                   void *conf);

#endif /* _NGX_STREAM_INJECT_MODULE_H_ */
