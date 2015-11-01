#include <stdio.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/sockios.h>
#endif

#include <netdb.h>
#include <json-c/json.h>
#include <zlib.h>

#include "apache20.h"
#include "functions.h"
#include "functions20.h"

#include "mod_log_gelf.h"

#define DEFAULT_LOG_FMT "ABDhmsvRti"
#define UDP 0
#define TCP 1 
#define RECONNECT_INTERVAL 500000
#define MIN_CONNECTIONS 1
#define MAX_CONNECTIONS 5
#define SEND_BUFFER 1048576

module AP_MODULE_DECLARE_DATA log_gelf_module;

static int verbose = 0;
static char errbuf[1024];

typedef struct {
  char key;               /* item letter character */
  item_func  *func;       /* its extraction function */
  const char *arg;        /* one string argument for func */
  const char *field_name; /* GELF extra field name */
} log_item;

typedef struct {
  apr_socket_t   			*s;                 /* Actual GELF connection */
  apr_sockaddr_t 			*sa;                /* GELF Address */
} gelf_connection;

typedef struct {
  int             		enabled;
  int             		port;            /* GELF port */
  int             		protocol;        /* 0=UDP 1=TCP */
  const char      		*server;         /* Hostname/IP of Graylog server */
  const char      		*source;         /* Source field */
  const char      		*facility;       /* Facility field */
  const char      		*tag;            /* Optional tag field */
  const char      		*fields;         /* String with fields of interest */
  const char      		*cookie;         /* Log this cookie */
  log_item        		**parsed_fields; /* Link fields to extractor function */
  apr_pool_t      		*parse_pool;     /* memory pool for option parsing */
  apr_reslist_t  			*connection_pool;
  int            			nmin;
  int            			nkeep;
  int            			nmax;
  apr_interval_time_t ttl;
} gelf_config;

static apr_array_header_t *log_item_list;

/* module configuration */
static void *create_gelf_configuration(apr_pool_t *pool, server_rec *server) {
  gelf_config *config = apr_pcalloc(pool, sizeof(gelf_config));
  config->source = "localhost";
  config->facility = "apache-gelf";
  config->fields = DEFAULT_LOG_FMT;
	/* connection pool settings */
  config->nmin = MIN_CONNECTIONS;
  config->nkeep = MIN_CONNECTIONS;
  config->nmax = MAX_CONNECTIONS;
  config->ttl = RECONNECT_INTERVAL;

  apr_pool_create(&config->parse_pool, pool);

  return config;
}

static void *merge_gelf_configuration(apr_pool_t *p, void *parent, void *new) {
  return parent;
}

/* Registration function for extract functions */
void log_gelf_register_item(server_rec *server, apr_pool_t *p,
    char key, item_func *func, const char *arg, const char *field_name) {
  gelf_config *config = ap_get_module_config(server->module_config, &log_gelf_module);
  log_item *item;
  int i, length;

  if (!log_item_list)
    log_item_list = apr_array_make(p, 25, sizeof(log_item));

  item = apr_array_push(log_item_list);
  item->key = key;
  item->func = func;
  item->field_name = field_name;
  if (arg)
    item->arg = arg;
  
  length = strlen(config->fields);
  for (i = 0; i<length; i++) {
    char *pos;
    if ( (pos = ap_strchr_c(config->fields, key)) != NULL) {
        config->parsed_fields[pos - config->fields] = item;
      }
  }
}

/* Enable GELF logging module */
static const char *set_gelf_enabled(cmd_parms *cmd, void *cfg, int flag)
{
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);
  config->enabled = flag;
  return NULL;
}

/* Sets basic connection info */
static const char *set_gelf_connection_parameter(cmd_parms *cmd, void *cfg, const char *arg) {
  apr_uri_t uri;
  apr_uri_parse(cmd->pool, arg, &uri);
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);

  if (apr_strnatcmp(uri.scheme, "udp") == 0) {
    config->protocol = UDP;
  }

  if (apr_strnatcmp(uri.scheme, "tcp") == 0) {
    config->protocol = TCP;
  }

  if (config->protocol != UDP && config->protocol != TCP) {
    log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
      "mod_log_gelf: Server protocol is %s, but must be 'udp://' or 'tcp://', disable module.",
      uri.scheme);
    config->enabled = 0;
  }

  if (uri.hostname) {
    config->server = uri.hostname;
  }

  if (uri.port) {
    config->port = uri.port;
  }

  return NULL;
}

/* Set additional tag field for server identification */
static const char *set_gelf_tag(cmd_parms *cmd, void *cfg, const char *arg) {
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);
  config->tag = arg;
  return NULL;
}

/* Override source field */
static const char *set_gelf_source(cmd_parms *cmd, void *cfg, const char *arg) {
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);
  config->source = arg;
  return NULL;
}

/* Override facilityfield */
static const char *set_gelf_facility(cmd_parms *cmd, void *cfg, const char *arg) {
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);
  config->facility = arg;
  return NULL;
}

/* Override log format string */
static const char *set_gelf_fields(cmd_parms *cmd, void *cfg, const char *arg) {
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);
  config->fields = arg;
  return NULL;
}

/* Override log format string */
static const char *set_gelf_cookie(cmd_parms *cmd, void *cfg, const char *arg) {
  gelf_config *config = ap_get_module_config(cmd->server->module_config, &log_gelf_module);
  config->cookie = arg;
  return NULL;
}

static const command_rec log_gelf_directives[] = {
  AP_INIT_FLAG("GelfEnabled", set_gelf_enabled, NULL, RSRC_CONF, "Enable or disable GELF logging"),
  AP_INIT_TAKE1("GelfUrl", set_gelf_connection_parameter, NULL, RSRC_CONF, "The URL to a Graylog server"),
  AP_INIT_TAKE1("GelfSource", set_gelf_source, NULL, RSRC_CONF, "Override source field"),
  AP_INIT_TAKE1("GelfFacility", set_gelf_facility, NULL, RSRC_CONF, "Override facility field"),
  AP_INIT_TAKE1("GelfTag", set_gelf_tag, NULL, RSRC_CONF, "Set a identification tag"),
  AP_INIT_TAKE1("GelfFields", set_gelf_fields, NULL, RSRC_CONF, "List of fields that should be logged"),
  AP_INIT_TAKE1("GelfCookie", set_gelf_cookie, NULL, RSRC_CONF, "Add this cookie the log message"),
  { NULL }
};

/* Connection pool */
static gelf_connection* log_gelf_connection_acquire(request_rec* r) {
  gelf_config* config = ap_get_module_config(r->server->module_config, &log_gelf_module) ;
  apr_status_t rv;
	gelf_connection *con;
	
  rv = apr_reslist_acquire(config->connection_pool, (void**)&con);
  if ( rv != APR_SUCCESS ) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
      "mod_log_gelf: Failed to acquire GELF connection from pool %s",
       apr_strerror(rv, errbuf, sizeof(errbuf)));
       return NULL;
  }
	
  return con;
}

static apr_status_t log_gelf_connection_release(request_rec* r, gelf_connection *con) {
	gelf_config* config = ap_get_module_config(r->server->module_config, &log_gelf_module);
	apr_status_t rv;
	rv = apr_reslist_release(config->connection_pool, con);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_log_gelf: Can not release GELF socket.");
	}
	
	return rv;
}

static apr_status_t log_gelf_get_gelf_connection(gelf_connection *gc, gelf_config *config, apr_pool_t *pool) {
  apr_status_t rv;
  int proto = NULL;
	int type = NULL;

  if (config->protocol == TCP) {
    proto = APR_PROTO_TCP;
    type  = SOCK_STREAM;
  } else if (config->protocol == UDP) {
    proto = APR_PROTO_UDP;
    type  = SOCK_DGRAM;
  }

  if (verbose > 0) {
    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool,
      "mod_log_gelf: Connecting to server %s", config->server);
  }

  rv = apr_sockaddr_info_get(&gc->sa, config->server, APR_INET, config->port, 0, pool);
  if (rv != APR_SUCCESS) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
      "mod_log_gelf: Error setting GELF recipient %s:%d", config->server, config->port);
    return rv;
  }

  rv = apr_socket_create(&gc->s, gc->sa->family, type, proto, pool);
  if (rv != APR_SUCCESS) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
      "mod_log_gelf: Error opening GELF socket: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
    return rv;
  }

  rv = apr_socket_connect(gc->s, gc->sa);
  if (rv != APR_SUCCESS) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
      "mod_log_gelf: Error connecting to GELF port: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
    return rv;
  }

  /* set socket options */
  rv = apr_socket_opt_set(gc->s, APR_SO_SNDBUF, SEND_BUFFER);
  if (rv != APR_SUCCESS) {
    ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
      "mod_log_gelf: Error setting send buffer: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
    return rv;
  }

  if (config->protocol == TCP) {
    /* TCP socket options */
    rv = apr_socket_opt_set(gc->s, APR_SO_NONBLOCK, 0);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
        "mod_log_gelf: Error setting socket to blocking: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      return rv;
    }

    rv = apr_socket_opt_set(gc->s, APR_TCP_NODELAY, 1);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
        "mod_log_gelf: Error setting socket TCP nodelay: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      return rv;
    }

    rv = apr_socket_timeout_set(gc->s, 0);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
        "mod_log_gelf: Error setting socket timeout: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      return rv;
    }
  }

  return APR_SUCCESS;
}

static apr_status_t gelf_pool_construct(void** rs, void* params, apr_pool_t* pool) {
  gelf_config *config = (gelf_config*)params;
  apr_status_t rv;
	
	if (config->enabled < 1) {
		/* module disabled, no socket needed */
		return APR_SUCCESS;
	}
	
  if (verbose > 0) {
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool, "mod_log_gelf: Creating new socket for pool: %s:%d",
                  config->server, config->port);
  }

	gelf_connection *con;
	con = apr_palloc(pool, sizeof(gelf_connection));
	rv = log_gelf_get_gelf_connection(con, config, pool);
  if (rv != APR_SUCCESS) {
    return APR_EGENERAL;
  }

  *rs = con;

  if (!*rs ) {
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool, "mod_log_gelf: Failed to store socket in resource list");
    return APR_EGENERAL;
  }
  return APR_SUCCESS;
}

static apr_status_t gelf_pool_destruct(void* resource, void* params, apr_pool_t* pool) {
	if (resource) {
		gelf_connection *con = (gelf_connection*)resource;
  	apr_socket_close(con->s);
	}
  return APR_SUCCESS ;
}

/* Registered hooks */
static int log_gelf_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server) {
  gelf_config *config = ap_get_module_config(server->module_config, &log_gelf_module);

	/* initialize resource list to keep track of socket pool */
  if ( apr_reslist_create(&config->connection_pool,
                          config->nmin,
                          config->nkeep,
                          config->nmax,
                          config->ttl,
                          gelf_pool_construct,
                          gelf_pool_destruct,
                          config, p) != APR_SUCCESS ) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, server, "mod_log_gelf: Failed to initialize resource pool, disabling GELF logging.");
		config->enabled = 0;
		return OK;
  }
  apr_pool_cleanup_register(p, config->connection_pool,
                            (void*)apr_reslist_destroy, apr_pool_cleanup_null);

  /* allocate memory for log items */
  config->parsed_fields = apr_pcalloc(config->parse_pool, strlen(config->fields) * sizeof(log_item *));

  /* register available logging fields */
  log_gelf_register_item(server,p,'A', extract_agent,             NULL, "_agent");
  log_gelf_register_item(server,p,'a', extract_request_query,     NULL, "_request_args");
  log_gelf_register_item(server,p,'B', extract_bytes_sent,        NULL, "_bytes_send");
  log_gelf_register_item(server,p,'C', extract_connection_status, NULL, "_connection_status");
  log_gelf_register_item(server,p,'c', extract_specific_cookie,   config->cookie, "_cookie");
  log_gelf_register_item(server,p,'D', extract_request_duration,  NULL, "_request_duration_ms");
  log_gelf_register_item(server,p,'f', extract_request_file,      NULL, "_request_file");
  log_gelf_register_item(server,p,'H', extract_request_protocol,  NULL, "_request_protocol");
  log_gelf_register_item(server,p,'h', extract_remote_host,       NULL, "_remote_host");
  log_gelf_register_item(server,p,'i', extract_remote_address,    NULL, "_remote_address");
  log_gelf_register_item(server,p,'L', extract_local_address,     NULL, "_local_address");
  log_gelf_register_item(server,p,'l', extract_remote_logname,    NULL, "_remote_login_name");
  log_gelf_register_item(server,p,'m', extract_request_method,    NULL, "_request_method");
  log_gelf_register_item(server,p,'p', extract_server_port,       NULL, "_server_port");
  log_gelf_register_item(server,p,'P', extract_child_pid,         NULL, "_child_pid");
  log_gelf_register_item(server,p,'R', extract_referer,           NULL, "_referer");
  log_gelf_register_item(server,p,'r', extract_request_line,      NULL, "_request_line");
  log_gelf_register_item(server,p,'s', extract_status,            NULL, "_status");
  log_gelf_register_item(server,p,'t', extract_request_time,      NULL, "_request_time");
  log_gelf_register_item(server,p,'U', extract_request_uri,       NULL, "_request_uri");
  log_gelf_register_item(server,p,'u', extract_remote_user,       NULL, "_remote_user");
  log_gelf_register_item(server,p,'V', extract_server_name,       NULL, "_server_name");
  log_gelf_register_item(server,p,'v', extract_virtual_host,      NULL, "_virtual_host");
  
  return OK;
}

static int log_gelf_transaction(request_rec *request) {
  transferData* tdata;
  gelf_config *config = ap_get_module_config(request->server->module_config, &log_gelf_module);

  /* skip logging if module is disabled or no connection parameters are given */
  if (config->enabled == 0) {
    log_error(APLOG_MARK, APLOG_NOTICE, 0, request->server,
      "mod_log_gelf: Module is disbaled, not sending log data!");
    return OK;
  }
	
  /* skip logging if endpoint is not configured properly */
  if (!config->server || !config->port) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: 'GelfUrl' not set in server configuration. Use the format 'protocol://ip:port'");
    return OK;
  }

  char* json = log_gelf_make_json(request);
  if (config->protocol == TCP) {
    /* allocate memory for actual log message */
    tdata = apr_palloc(request->pool, sizeof(transferData));
    memset(tdata, 0, sizeof(transferData));
    tdata->data = json;
    tdata->size = strlen(json);
    log_gelf_send_message_tcp(tdata, request);
  } else if (config->protocol == UDP) {
    tdata = log_gelf_zlib_compress(json, request);
    log_gelf_send_message_udp(tdata, request);
  }

  return OK;
}

char * log_gelf_make_json(request_rec *request) {
  int i, length;
  gelf_config *config = ap_get_module_config(request->server->module_config, &log_gelf_module);

  /* init json object */
  json_object* object = json_object_new_object();
  
  /* attach field pairs to json root */
  json_add_string(object, "version", "1.1");
  json_add_string(object, "host", config->source);
  json_add_string(object, "short_message", extract_request_line(request, NULL));
  json_add_string(object, "facility", config->facility);
  json_add_int(object, "level", 6); /*0=Emerg, 1=Alert, 2=Crit, 3=Error, 4=Warn, 5=Notice, 6=Info */
  json_add_double(object, "timestamp", log_gelf_get_timestamp());

  /* add extra fields */
  length = strlen(config->fields);
  for (i = 0; i<length; i++) {
    log_item *item = config->parsed_fields[i];
    if (item != NULL) {
      if (item->arg)
        json_add_string(object, item->field_name, item->func(request, (char*)item->arg));
      else
        json_add_string(object, item->field_name, item->func(request, ""));
    }
  }

  /* add conditional fields */
  if (config->tag) {
    json_add_string(object, "_tag", config->tag);
  }

  /* get json string */
  const char * str = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);

  /* free temporary json object */
  json_object_put(object);

  return apr_pstrdup(request->pool, str);
}

json_object * json_add_string(json_object *jobj, const char *key, const char *value) {
  json_object *jstring = json_object_new_string(value);
  json_object_object_add(jobj, key, jstring);

  return jobj;
}

json_object * json_add_int(json_object *jobj, const char *key, int value) {
  json_object *jint = json_object_new_int(value);
  json_object_object_add(jobj, key, jint);

  return jobj;
}

json_object * json_add_double(json_object *jobj, const char *key, double value) {
  json_object *jdouble = json_object_new_double(value);
  json_object_object_add(jobj, key, jdouble);

  return jobj;
}

transferData* log_gelf_zlib_compress(const char *line, request_rec *request) {
  /* init stream struc and buffers */
  z_stream* strm;
  size_t len = strlen(line);
  void * buf = apr_palloc(request->pool, len);

  strm = apr_palloc(request->pool, sizeof(z_stream));
  memset(strm, 0, sizeof(z_stream));
  strm->zalloc = Z_NULL;
  strm->zfree = Z_NULL;
  strm->opaque = Z_NULL;
  strm->data_type = Z_TEXT;

  /* deflate log message */
  if (deflateInit(strm, 6) != Z_OK) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Error initialising zlib deflate");
  }
  strm->avail_in = len;
  strm->next_in = (void *)line;
  strm->next_out = buf;
  strm->avail_out = len;
  if ( deflate(strm, Z_FINISH) == Z_STREAM_ERROR) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Error compressing with zlib deflate");
  }
  int csize = len - strm->avail_out;
  if (verbose > 0) {
    log_error(APLOG_MARK, APLOG_NOTICE, 0, request->server,
      "mod_log_gelf: Json length: %i, compressed: %i", (int)len, csize);
  }
  deflateEnd(strm);

  /* create data to transfer */
  transferData * ret = apr_palloc(request->pool, sizeof(transferData));
  memset(ret, 0, sizeof(transferData));
  ret->data = buf;
  ret->size = csize;

  return ret;
}

void log_gelf_send_message_udp(const transferData* payload, request_rec *request) {
  apr_status_t rv;
  apr_size_t len;
  gelf_config *config = ap_get_module_config(request->server->module_config, &log_gelf_module);

  if (payload->size > 0) {
    len = payload->size;
  } else {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Got empty log message, not sending anything.");
		return;
  }

	/* acquire a free socket, send message, release socket */
  gelf_connection *con = log_gelf_connection_acquire(request);
	if (!con) {
		return;
	}
  
  if (verbose > 0) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Sending GELF message: %s", (char*)payload->data);
  }

  rv = apr_socket_send(con->s, payload->data, &len);
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Error writing to socket %d bytes. Error %s",
      payload->size, apr_strerror(rv, errbuf, sizeof(errbuf)));
  }

	log_gelf_connection_release(request, con);
}

void log_gelf_send_message_tcp(const transferData* payload, request_rec *request) {
  apr_status_t rv;
  apr_size_t len;
  gelf_config *config = ap_get_module_config(request->server->module_config, &log_gelf_module);

  if (payload->size > 0) {
    /* one extra byte for string termination */
    len = payload->size + 1;
  } else {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Got empty log message, not sending anything.");
    return;
  }

  /* copy payload and append '\0' */
  const char* gelf_payload = apr_pstrmemdup(request->pool, payload->data, payload->size);

	/* acquire a free socket, send message, release socket */
  gelf_connection *con = log_gelf_connection_acquire(request);
	if (!con) {
		return;
	}
  
  if (verbose > 0) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Sending GELF message: %s", gelf_payload);
  }

  rv = apr_socket_send(con->s, gelf_payload, &len);
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Error writing to socket %d bytes. Error %s",
      payload->size, apr_strerror(rv, errbuf, sizeof(errbuf)));
			apr_reslist_invalidate(config->connection_pool, con) ;
  }
	
	log_gelf_connection_release(request, con);
}

double log_gelf_get_timestamp() {
  return ((double) (apr_time_now() / 1000)) / 1000.0;
}

static void log_gelf_child_init(apr_pool_t *p, server_rec *server) {
  apr_status_t rv;
  gelf_config *config = ap_get_module_config(server->module_config, &log_gelf_module);

  if (verbose > 0) {
    log_error(APLOG_MARK, APLOG_NOTICE, 0, server,
        "mod_log_gelf: Initializing new child process.");
  }

  if (config->server == NULL) {
    log_error(APLOG_MARK, APLOG_NOTICE, 0, server,
        "mod_log_gelf: Creating new configuration.");
    gelf_config *config = create_gelf_configuration(p, server);
    ap_set_module_config(server->module_config, &log_gelf_module, config);
  }
}

static void register_hooks(apr_pool_t *p) {
  ap_hook_post_config(log_gelf_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
  ap_hook_child_init(log_gelf_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(log_gelf_transaction, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA log_gelf_module = { 
    STANDARD20_MODULE_STUFF,
    NULL,                       /* Per-directory configuration handler */
    NULL,                       /* Merge handler for per-directory configurations */
    create_gelf_configuration,  /* Per-server configuration handler */
    merge_gelf_configuration,   /* Merge handler for per-server configurations */
    log_gelf_directives,        /* Any directives we may have for httpd */
    register_hooks              /* Our hook registering function */
};
