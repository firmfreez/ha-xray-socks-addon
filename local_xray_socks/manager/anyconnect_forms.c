/* Observe public form metadata before the stock CLI answers it.
 * Never inspect values, hidden inputs, banners, URLs or server responses. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openconnect.h>

static openconnect_process_auth_form_vfn original_form;

static const char *identifier(const char *value)
{
    if (!value || !*value || strlen(value) > 64)
        return "[unavailable]";
    for (const unsigned char *p = (const unsigned char *)value; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-'))
            return "[unavailable]";
    return value;
}

static int observe_form(void *data, struct oc_auth_form *form)
{
    unsigned count = 0;
    fprintf(stderr, "AnyConnect form: id=%s; server_error=%s\n",
            identifier(form->auth_id), form->error && *form->error ? "yes" : "no");
    for (struct oc_form_opt *opt = form->opts; opt && count++ < 32; opt = opt->next) {
        if ((opt->flags & OC_FORM_OPT_IGNORE) || opt->type == OC_FORM_OPT_HIDDEN)
            continue;
        const char *type = opt->type == OC_FORM_OPT_PASSWORD ? "password" :
                           opt->type == OC_FORM_OPT_TEXT ? "text" :
                           opt->type == OC_FORM_OPT_SELECT ? "select" : "other";
        fprintf(stderr, "AnyConnect field: %s:%s; type=%s\n",
                identifier(form->auth_id), identifier(opt->name), type);
    }
    fflush(stderr);
    int result = original_form(data, form);
    fprintf(stderr, "AnyConnect form result: id=%s; result=%d\n",
            identifier(form->auth_id), result);
    return result;
}

struct openconnect_info *openconnect_vpninfo_new(const char *agent,
        openconnect_validate_peer_cert_vfn cert,
        openconnect_write_new_config_vfn config,
        openconnect_process_auth_form_vfn form,
        openconnect_progress_vfn progress, void *data)
{
    typedef struct openconnect_info *(*create_fn)(const char *,
        openconnect_validate_peer_cert_vfn, openconnect_write_new_config_vfn,
        openconnect_process_auth_form_vfn, openconnect_progress_vfn, void *);
    create_fn create = (create_fn)dlsym(RTLD_NEXT, "openconnect_vpninfo_new");
    if (!create) {
        fputs("AnyConnect: cannot initialize form diagnostics\n", stderr);
        exit(1);
    }
    original_form = form;
    return create(agent, cert, config, form ? observe_form : NULL, progress, data);
}
