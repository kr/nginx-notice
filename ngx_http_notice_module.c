
/*
 * Copyright 2007 Keith Rarick <kr@xph.us>
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

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


static u_char  ngx_notice[] = { 'g', 'o', 'o', 'd', '\n', '\n' };


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
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    ngx_http_notice_conf_t *nlcf;

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

    b->pos = ngx_notice;
    b->last = ngx_notice + sizeof(ngx_notice);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = sizeof(ngx_notice);
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

