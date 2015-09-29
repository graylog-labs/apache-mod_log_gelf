typedef const char *item_func(request_rec *r, char *a);
typedef struct transferDataS {
    void * data;
    int size;
} transferData;
transferData* log_gelf_zlib_compress(const char* line, request_rec *request);

static const char* set_gelf_enabled(cmd_parms *cmd, void *cfg, int flag);
static const char* set_gelf_connection_parameter(cmd_parms *cmd, void *cfg, const char *arg);
static const char* set_gelf_tag(cmd_parms *cmd, void *cfg, const char *arg);
static const char* set_gelf_source(cmd_parms *cmd, void *cfg, const char *arg);
static const char* set_gelf_facility(cmd_parms *cmd, void *cfg, const char *arg);
static const char* set_gelf_fields(cmd_parms *cmd, void *cfg, const char *arg);
static const char* set_gelf_cookie(cmd_parms *cmd, void *cfg, const char *arg);

void log_gelf_register_item(server_rec *s, apr_pool_t *p,
                char key, item_func *func, const char *arg, const char *field_name);
static int log_gelf_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void log_gelf_child_init(apr_pool_t *p, server_rec *s);
static int log_gelf_transaction(request_rec *request);
void log_gelf_send_message_udp(const transferData* payload, request_rec *request);
void log_gelf_send_message_tcp(const transferData* payload, request_rec *request);
void log_gelf_get_tcp_socket(request_rec *request);
apr_status_t log_gelf_close_link(void *data);

char* log_gelf_make_json(request_rec *request);
json_object* json_add_string(json_object *jobj, const char *key, const char *value);
json_object* json_add_int(json_object *jobj, const char *key, int value);
json_object* json_add_double(json_object *jobj, const char *key, double value);

double log_gelf_get_timestamp();
