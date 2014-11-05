
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "util_cookies.h"
#include "apr_strings.h"

int session_header_fixups(request_rec *r);
module AP_MODULE_DECLARE_DATA session_header_module;


typedef struct server_cfg {
    char *cookie_name;                  /* Location to which this record applies. */
} server_cfg_t;

static void *session_header_create_config (apr_pool_t *p, char *dummy)
{
    server_cfg_t *st = (server_cfg_t *)apr_pcalloc(p, sizeof(server_cfg_t));

    st->cookie_name = NULL;

    return st;
}

int session_header_fixups(request_rec *r) {
    server_cfg_t *conf = (server_cfg_t *)ap_get_module_config(r->per_dir_config, 
                                                &session_header_module);
    const char *val = NULL;
    char *unescaped;

    /* Get the cookie from the request */
    ap_cookie_read(r, conf->cookie_name, &val, 0);
    if (val == NULL) {
        return OK;
    }
    unescaped = apr_pstrdup(r->pool, val);

    ap_unescape_urlencoded(unescaped);
    apr_table_addn(r->headers_in, "Authorization", unescaped);
    return OK;
}

static void mod_session_header_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(session_header_fixups, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec session_header_cmds[] =
{
    AP_INIT_TAKE1("AuthenicateCookieName", ap_set_string_slot,
                  (void *) APR_OFFSETOF(server_cfg_t, cookie_name), RSRC_CONF,
                  "Name of the cookie to use when setting the Authorization header."),
    {NULL}
};

/* Dispatch list for API hooks */
AP_DECLARE_MODULE(session_header) = {
    STANDARD20_MODULE_STUFF, 
    session_header_create_config, /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    session_header_cmds,   /* table of config file commands       */
    mod_session_header_register_hooks  /* register hooks                      */
};

