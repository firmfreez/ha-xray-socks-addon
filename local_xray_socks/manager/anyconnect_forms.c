/* Observe public form metadata before the stock CLI answers it.
 * Never inspect values, hidden inputs, banners, URLs or server responses. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openconnect.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static openconnect_process_auth_form_vfn original_form;
static unsigned form_calls;
static unsigned primary_submissions;

/* Browser reports are private pipe data, never OpenConnect log output. */
static char *read_field(FILE *stream)
{
    char buf[65538];
    if (!fgets(buf, sizeof(buf), stream)) return NULL;
    size_t len = strlen(buf);
    if (!len || buf[len - 1] != '\n') return NULL;
    buf[len - 1] = 0;
    return strdup(buf);
}

static int open_sso(struct openconnect_info *vpn, const char *uri, void *data)
{
    (void)data;
    int pair[2], result = -EINVAL, completed = 0;
    if (!uri || strchr(uri, '\n') || socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return result;
    pid_t pid = fork();
    if (pid < 0) { close(pair[0]); close(pair[1]); return result; }
    if (!pid) {
        close(pair[0]);
        dup2(pair[1], STDIN_FILENO); dup2(pair[1], STDOUT_FILENO);
        close(pair[1]);
        unsetenv("LD_PRELOAD");
        execlp("python3", "python3", "/app/anyconnect_sso.py", (char *)NULL);
        _exit(127);
    }
    close(pair[1]);
    FILE *stream = fdopen(pair[0], "r+");
    if (stream) {
        fprintf(stream, "%s\n", uri); fflush(stream);
        for (;;) {
            char *url = read_field(stream), *count = read_field(stream);
            char *cookies[513] = {0};
            if (!url || !count) { free(url); free(count); break; }
            char *end = NULL;
            long n = strtol(count, &end, 10);
            int valid = *count && !*end && n >= 0 && n <= 256;
            free(count);
            if (valid) for (long i = 0; i < n * 2; i++) {
                cookies[i] = read_field(stream);
                if (!cookies[i]) { valid = 0; break; }
            }
            if (valid) {
                struct oc_webview_result report = { .uri = url, .cookies = (const char **)cookies, .headers = NULL };
                result = openconnect_webview_load_changed(vpn, &report);
                fprintf(stream, "%d\n", result); fflush(stream);
                if (result != -EAGAIN) completed = 1;
            }
            free(url);
            for (int i = 0; i < 512; i++) free(cookies[i]);
            if (!valid || result != -EAGAIN) break;
        }
        fclose(stream);
    } else close(pair[0]);
    /* A final report already tells Python to close Chromium. Interrupting its
     * finally block here can leave a frame or browser database behind. */
    if (!completed) kill(pid, SIGTERM);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    if (result) fputs("AnyConnect: SSO authentication failed or timed out\n", stderr);
    return result;
}

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
    int username = 0, password = 0, sso = 0;
    fprintf(stderr, "AnyConnect form: id=%s; server_error=%s\n",
            identifier(form->auth_id), form->error && *form->error ? "yes" : "no");
    for (struct oc_form_opt *opt = form->opts; opt && count++ < 32; opt = opt->next) {
        if ((opt->flags & OC_FORM_OPT_IGNORE) || opt->type == OC_FORM_OPT_HIDDEN)
            continue;
        if (opt->type == OC_FORM_OPT_SSO_TOKEN) sso = 1;
        if (opt->type == OC_FORM_OPT_TEXT && opt->name && !strcmp(opt->name, "username"))
            username = 1;
        if (opt->type == OC_FORM_OPT_PASSWORD && opt->name && !strcmp(opt->name, "password"))
            password = 1;
        const char *type = opt->type == OC_FORM_OPT_PASSWORD ? "password" :
                           opt->type == OC_FORM_OPT_TEXT ? "text" :
                           opt->type == OC_FORM_OPT_SELECT ? "select" : "other";
        fprintf(stderr, "AnyConnect field: %s:%s; type=%s\n",
                identifier(form->auth_id), identifier(opt->name), type);
    }
    fflush(stderr);
    if (getenv("ANYCONNECT_SSO_WORK")) {
        if (sso && ++form_calls <= 8) return OC_FORM_RESULT_OK;
        if (username || password) {
            fputs("AnyConnect: SSO authentication failed or timed out; server requested password login\n", stderr);
            return OC_FORM_RESULT_ERR;
        }
    }
    /* NEWGROUP re-enters the callback before any credentials are submitted.
     * A complete username/password form after an OK submission is a return
     * to primary login, not evidence that password should receive "push". */
    if ((username && password && primary_submissions) || ++form_calls > 8) {
        fputs("AnyConnect: authentication form repeated; automatic submission stopped\n", stderr);
        return OC_FORM_RESULT_ERR;
    }
    int result = original_form(data, form);
    if (result == OC_FORM_RESULT_OK && username && password)
        primary_submissions++;
    if (result == OC_FORM_RESULT_OK) {
        unsigned fields = 0;
        for (struct oc_form_opt *opt = form->opts; opt && fields++ < 32; opt = opt->next) {
            if (opt->type != OC_FORM_OPT_TEXT && opt->type != OC_FORM_OPT_PASSWORD)
                continue;
            if (opt->flags & OC_FORM_OPT_IGNORE)
                continue;
            fprintf(stderr, "AnyConnect field ready: %s:%s; populated=%s\n",
                    identifier(form->auth_id), identifier(opt->name),
                    opt->_value && *opt->_value ? "yes" : "no");
        }
    }
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
    form_calls = primary_submissions = 0;
    struct openconnect_info *vpn = create(agent, cert, config, form ? observe_form : NULL, progress, data);
    if (vpn && getenv("ANYCONNECT_SSO_WORK")) openconnect_set_webview_callback(vpn, open_sso);
    return vpn;
}
