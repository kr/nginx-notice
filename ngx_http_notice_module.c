
/*
 * Copyright 2007 Keith Rarick <kr@xph.us>
 * Copyright (C) Igor Sysoev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NOTICE_BUF_SIZE 102400 /* 100KiB */

#define ALLOWED_METHODS (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_PUT|NGX_HTTP_POST)

static void *
ngx_http_notice_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_notice_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *
ngx_http_notice_post_handler(ngx_conf_t *cf, void *data, void *conf);

typedef struct {
    ngx_str_t path;
    ngx_str_t type;
} ngx_http_notice_conf_t;

static ngx_conf_post_t ngx_http_notice_post = {
  ngx_http_notice_post_handler,
};

static ngx_command_t  ngx_http_notice_commands[] = {

    { ngx_string("notice"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_notice_conf_t, path),
      &ngx_http_notice_post },

    { ngx_string("notice_type"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_notice_conf_t, type),
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_notice_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_notice_create_loc_conf,/* create location configuration */
    ngx_http_notice_merge_loc_conf, /* merge location configuration */
};


ngx_module_t  ngx_http_notice_module = {
    NGX_MODULE_V1,
    &ngx_http_notice_module_ctx, /* module context */
    ngx_http_notice_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_notice_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_notice_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_notice_conf_t));
    if (conf == NULL) return NGX_CONF_ERROR;

    /*
     * Set by ngx_pcalloc():
     *
     *     conf->path.len = 0;
     *     conf->path.data = NULL;
     *     conf->type.len = 0;
     *     conf->type.data = NULL;
     */

    return conf;
}

static char *
ngx_http_notice_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_notice_conf_t *prev = parent;
    ngx_http_notice_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_str_value(conf->type, prev->type, "text/html");

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_notice_handler(ngx_http_request_t *r)
{
    ngx_int_t     rc, n;
    ngx_fd_t      fd;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    ngx_http_notice_conf_t *nlcf;
    u_char notice[NOTICE_BUF_SIZE];

    nlcf = ngx_http_get_module_loc_conf(r, ngx_http_notice_module);

    if (!(r->method & ALLOWED_METHODS)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    r->headers_out.content_type = nlcf->type;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    fd = ngx_open_file(nlcf->path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        /* TODO: log an error */
        return NGX_HTTP_NOT_FOUND;
    }

    n = ngx_read_fd(fd, notice, NOTICE_BUF_SIZE);
    if (n == NGX_FILE_ERROR) {
        /* TODO: log an error */
        return NGX_HTTP_NOT_FOUND;
    }

    b->pos = notice;
    b->last = notice + n;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = n;
    r->headers_out.last_modified_time = 23349600;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_notice_post_handler(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_notice_handler;

    return NGX_CONF_OK;
}

