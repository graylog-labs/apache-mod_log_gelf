typedef const json_object* item_func(request_rec *r, char *a);
typedef struct transferDataS {
    void * data;
    int size;
} transferData;
transferData* log_gelf_zlib_compress(const char* line, request_rec *request);
char* log_gelf_make_json(request_rec *request);
json_object* json_add_string(json_object *jobj, const char *key, const char *value);
json_object* json_add_int(json_object *jobj, const char *key, int value);
json_object* json_add_double(json_object *jobj, const char *key, double value);

void log_gelf_register_item(server_rec *s, apr_pool_t *p,
                char key, item_func *func, const char *arg, const char *field_name);
void log_gelf_send_message_udp(const transferData* payload, request_rec *request);
void log_gelf_send_message_tcp(const transferData* payload, request_rec *request);

double log_gelf_get_timestamp();
