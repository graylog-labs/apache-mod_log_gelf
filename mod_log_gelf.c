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
#define RECONNECT_INTERVAL 5000000
#define SEND_BUFFER 1048576

module AP_MODULE_DECLARE_DATA log_gelf_module;

int verbose = 0;
char errbuf[256];

typedef struct {
  char key;               /* item letter character */
  item_func  *func;       /* its extraction function */
  const char *arg;        /* one string argument for func */
  const char *field_name; /* GELF extra field name */
} log_item;

typedef struct {
  int         enabled;
  int         port;           /* GELF port */
  int         protocol;       /* 0=UDP 1=TCP */
  const char *server;         /* Hostname/IP of Graylog server */
  const char *source;         /* Source field */
  const char *facility;       /* Facility field */
  const char *tag;            /* Optional tag field */
  const char *fields;         /* String with fields of interest */
  const char *cookie;         /* Log this cookie */
  log_item   **parsed_fields; /* Link fields to extractor function */
  apr_pool_t *parse_pool;     /* memory pool for option parsing */
} gelf_config;

typedef struct {
  apr_socket_t   *s;                 /* Actual GELF connection */
  apr_sockaddr_t *sa;                /* GELF Address */
  apr_socket_t   *s_t;               /* Socket for testing endpoint */
  apr_sockaddr_t *sa_t;
  apr_thread_t   *reconnect_handler; /* Parallel thread to check endpoint availablility */
  int            connected;          /* Whether we are connected to a GELF server or not */
  int            reachable;          /* GELF server is reachable */
  int            shutdown;           /* indicates process shutdown */
  apr_pool_t     *socket_pool;       /* memory pool for option parsing */
} gelf_connection;

/* configuration object */  
static gelf_config config;

/*  network sockets for sending data and testing endpoint */
static gelf_connection connection;

/* list of "handlers" for log types */
static apr_array_header_t *log_item_list;

/* Registration function for extract functions */
void log_gelf_register_item(server_rec *s, apr_pool_t *p,
    char key, item_func *func, const char *arg, const char *field_name) {
  server_rec *ts;
  log_item *item;
  int i, length;

  if (!log_item_list)
    log_item_list = apr_array_make(p, 10, sizeof(log_item));

  item = apr_array_push(log_item_list);
  item->key = key;
  item->func = func;
  item->field_name = field_name;
  if (arg)
    item->arg = arg;
  
  length = strlen(config.fields);
  for (i = 0; i<length; i++) {
    char *pos;
    if ( (pos = ap_strchr_c(config.fields, key)) != NULL) {
        config.parsed_fields[pos - config.fields] = item;
      }
  }
}

/* Enable GELF logging module */
static const char *set_gelf_enabled(cmd_parms *cmd, void *cfg, int flag)
{
    config.enabled = flag;
    return NULL;
}

/* Sets basic connection info */
static const char *set_gelf_connection_parameter(cmd_parms *cmd, void *cfg, const char *arg) {
  apr_uri_t uri;
  apr_uri_parse(cmd->pool, arg, &uri);

  if (apr_strnatcmp(uri.scheme, "udp") == 0) {
    config.protocol = UDP;
  }

  if (apr_strnatcmp(uri.scheme, "tcp") == 0) {
    config.protocol = TCP;
  }

  if (config.protocol != UDP && config.protocol != TCP) {
    log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
      "mod_log_gelf: Server protocol is %s, but must be 'udp://' or 'tcp://', disable module.",
      uri.scheme);
    config.enabled = 0;
  }

  if (uri.hostname) {
    config.server = uri.hostname;
  }

  if (uri.port) {
    config.port = uri.port;
  }

  return NULL;
}

/* Set additional tag field for server identification */
static const char *set_gelf_tag(cmd_parms *cmd, void *cfg, const char *arg) {
  config.tag = arg;
  return NULL;
}

/* Override source field */
static const char *set_gelf_source(cmd_parms *cmd, void *cfg, const char *arg) {
  config.source = arg;
  return NULL;
}

/* Override facilityfield */
static const char *set_gelf_facility(cmd_parms *cmd, void *cfg, const char *arg) {
  config.facility = arg;
  return NULL;
}

/* Override log format string */
static const char *set_gelf_fields(cmd_parms *cmd, void *cfg, const char *arg) {
  config.fields = arg;
  return NULL;
}

/* Override log format string */
static const char *set_gelf_cookie(cmd_parms *cmd, void *cfg, const char *arg) {
  config.cookie = arg;
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

/* Registered hooks */
static int log_gelf_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server) {
  /* source field defaults to server name */
  if (!config.source) {
    config.source = apr_pstrdup(p, (char *)server->server_hostname);
  }

  /* facility defaults to 'apache-gelf' */
  if (!config.facility) {
    config.facility = "apache-gelf";
  }
 
  /* default logging fields */
  if (!config.fields) {
    config.fields = DEFAULT_LOG_FMT;
  }

  /* no default cookie set */
  if (!config.cookie) {
    config.cookie = "";
  }

  /* we got the shutdown signal */
  if (!connection.shutdown) {
    connection.shutdown = 0;
  }

  /* by default we are not connected */
  if (!connection.connected) {
    connection.connected = 0;
  }

  /* and the endpoint is not reachable */
  if (!connection.reachable) {
    connection.reachable = 0;
  }

  /* allocate memory for log_items */
  apr_pool_create(&config.parse_pool, p);
  config.parsed_fields = apr_pcalloc(config.parse_pool, strlen(config.fields) * sizeof(log_item *));

  /* register available logging fields */
  log_gelf_register_item(server,p,'A', extract_agent,             NULL, "_agent");
  log_gelf_register_item(server,p,'a', extract_request_query,     NULL, "_request_args");
  log_gelf_register_item(server,p,'B', extract_bytes_sent,        NULL, "_bytes_send");
  log_gelf_register_item(server,p,'C', extract_connection_status, NULL, "_connection_status");
  log_gelf_register_item(server,p,'c', extract_specific_cookie,   config.cookie, "_cookie");
  log_gelf_register_item(server,p,'D', extract_request_duration,  NULL, "_request_duration_ms");
  log_gelf_register_item(server,p,'f', extract_request_file,      NULL, "_request_file");
  log_gelf_register_item(server,p,'H', extract_request_protocol,  NULL, "_request_protocol");
  log_gelf_register_item(server,p,'h', extract_remote_host,       NULL, "_remote_host");
  log_gelf_register_item(server,p,'i', extract_remote_address,    NULL, "_remote_address");
  log_gelf_register_item(server,p,'L', extract_local_address,     NULL, "_local_address");
  log_gelf_register_item(server,p,'l', extract_remote_logname,    NULL, "_remote_login_name");
  log_gelf_register_item(server,p,'m', extract_request_method,    NULL, "_request_method");
  log_gelf_register_item(server,p,'p', extract_server_port,       NULL, "_server_port");
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
  /* skip logging if module is disabled or no connection parameters are given */
  if (config.enabled == 0) {
    log_error(APLOG_MARK, APLOG_NOTICE, 0, request->server,
      "mod_log_gelf: Module is disbaled, not sending log data!");
    return OK;
  }

  /* skip logging if there is no connection to a GELF endpoint */
  if (connection.connected == 0 && config.protocol == TCP) {
    return OK;
  }

  /* skip logging if endpoint is not configured properly */
  if (!config.server || !config.port) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: 'GelfUrl' not set in server configuration. Use the format 'protocol://ip:port'");
    return OK;
  }


  char* json = log_gelf_make_json(request);

  transferData* tdata;
  if (config.protocol == TCP) {
    /* allocate memory for actual log message */
    tdata = apr_palloc(request->pool, sizeof(transferData));
    memset(tdata, 0, sizeof(transferData));
    tdata->data = json;
    tdata->size = strlen(json);
    log_gelf_send_message_tcp(tdata, request);
  } else if (config.protocol == UDP) {
    tdata = log_gelf_zlib_compress(json, request);
    log_gelf_send_message_udp(tdata, request);
  }
}

char * log_gelf_make_json(request_rec *request) {
  int i, length;

  /* init json object */
  json_object* object = json_object_new_object();
  
  /* attach field pairs to json root */
  json_add_string(object, "version", "1.1");
  json_add_string(object, "host", config.source);
  json_add_string(object, "short_message", extract_request_line(request, NULL));
  json_add_string(object, "facility", config.facility);
  json_add_int(object, "level", 6); /*0=Emerg, 1=Alert, 2=Crit, 3=Error, 4=Warn, 5=Notice, 6=Info */
  json_add_double(object, "timestamp", log_gelf_get_timestamp());

  /* add extra fields */
  length = strlen(config.fields);
  for (i = 0; i<length; i++) {
    log_item *item = config.parsed_fields[i];
    if (item != NULL) {
      if (item->arg)
        json_add_string(object, item->field_name, item->func(request, (char*)item->arg));
      else
        json_add_string(object, item->field_name, item->func(request, ""));
    }
  }

  /* add conditional fields */
  if (config.tag) {
    json_add_string(object, "_tag", config.tag);
  }

  /* get json string */
  const char * str = json_object_to_json_string_ext(object,
      verbose ?
          JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED :
          JSON_C_TO_STRING_PLAIN);
  char * ret = apr_pstrdup(request->pool, str);

  /* free temporary json object */
  json_object_put(object);

  return ret;
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
  apr_size_t len = payload->size;

  if (connection.s)
    rv = apr_socket_send(connection.s, payload->data, &len);

  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Error writing to socket %d bytes. Error %s",
      payload->size, apr_strerror(rv, errbuf, sizeof(errbuf)));
  }
}

void log_gelf_send_message_tcp(const transferData* payload, request_rec *request) {
  apr_status_t rv;

  /* copy payload and append '\0' */
  const char* gelf_payload = apr_pstrmemdup(request->pool, payload->data, payload->size);
  apr_size_t len = payload->size + 1;

  if (connection.s)
    rv = apr_socket_send(connection.s, gelf_payload, &len);

  rv = APR_SUCCESS;
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, request->server,
      "mod_log_gelf: Error writing to socket %d bytes. Error %s",
      payload->size, apr_strerror(rv, errbuf, sizeof(errbuf)));
    connection.connected = 0;
  }
}

int log_gelf_get_socket(apr_pool_t *p, server_rec *server) {
  apr_status_t rv;
  int proto, type;

  if (config.protocol == TCP) {
    proto = APR_PROTO_TCP;
    type  = SOCK_STREAM;
  } else if (config.protocol == UDP) {
    proto = APR_PROTO_UDP;
    type  = SOCK_DGRAM;
  }

  if (verbose > 0) {
    log_error(APLOG_MARK, APLOG_NOTICE, 0, server,
      "mod_log_gelf: Connecting to server %s", config.server);
  }

  rv = apr_sockaddr_info_get(&connection.sa, config.server, APR_INET, config.port, 0, p);
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, server,
      "mod_log_gelf: Error setting GELF recipient %s:%d", config.server, config.port);
    return errno;
  }

  rv = apr_socket_create(&connection.s, connection.sa->family, type, proto, p);
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, server,
      "mod_log_gelf: Error opening GELF socket: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
    return errno;
  }

  rv = apr_socket_connect(connection.s, connection.sa);
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, server,
      "mod_log_gelf: Error connecting to GELF port: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
    return errno;
  }

  /* set socket options */
  rv = apr_socket_opt_set(connection.s, APR_SO_SNDBUF, SEND_BUFFER);
  if (rv != APR_SUCCESS) {
    log_error(APLOG_MARK, APLOG_ERR, 0, server,
      "mod_log_gelf: Error setting send buffer: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
    return errno;
  }

  if (config.protocol == TCP) {
  /* TCP socket options */
    rv = apr_socket_opt_set(connection.s, APR_SO_NONBLOCK, 0);
    if (rv != APR_SUCCESS) {
      log_error(APLOG_MARK, APLOG_ERR, 0, server,
        "mod_log_gelf: Error setting socket to blocking: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      return errno;
    }

    rv = apr_socket_opt_set(connection.s, APR_TCP_NODELAY, 1);
    if (rv != APR_SUCCESS) {
      log_error(APLOG_MARK, APLOG_ERR, 0, server,
        "mod_log_gelf: Error setting socket TCP nodelay: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      return errno;
    }

    rv = apr_socket_timeout_set(connection.s, 0);
    if (rv != APR_SUCCESS) {
      log_error(APLOG_MARK, APLOG_ERR, 0, server,
        "mod_log_gelf: Error setting socket timeout: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      return errno;
    }
  }

  return APR_SUCCESS;
}

apr_status_t log_gelf_socket_close(apr_socket_t* socket) {
  apr_status_t rv;

  if (socket) {
    rv = apr_socket_close(socket);
    socket = NULL;
  }
  return rv;
}

double log_gelf_get_timestamp() {
  return ((double) (apr_time_now() / 1000)) / 1000.0;
}

/* connection health check runs in a separate thread */
static void* APR_THREAD_FUNC log_gelf_check_tcp_port(apr_thread_t *thd, void *server) {
  const int proto = APR_PROTO_TCP;
  const int type = SOCK_STREAM;
  apr_pool_t *tp;
  apr_pool_create(&tp, NULL);
  apr_status_t rv;

  apr_sockaddr_info_get(&connection.sa_t, config.server, APR_INET, config.port, 0, tp);

  while(connection.shutdown == 0) {
    apr_socket_create(&connection.s_t, connection.sa_t->family, type, proto, tp);
    rv = apr_socket_connect(connection.s_t, connection.sa_t);
    if (rv != APR_SUCCESS) {
      log_error(APLOG_MARK, APLOG_ERR, 0, server,
        "mod_log_gelf: GELF connection lost: %s", apr_strerror(rv, errbuf, sizeof(errbuf)));
      connection.reachable = 0;
      connection.connected = 0;
    } else {
      connection.reachable = 1;
    }
    log_gelf_socket_close(connection.s_t);

    /* reconnect if GELF endpoint is reachable and we are not connected */
    if (connection.reachable && !connection.connected) {
      rv = log_gelf_get_socket(connection.socket_pool, server);
      if (rv == APR_SUCCESS) {
        connection.connected = 1;
      }
    }

    /* wait for next check interval */
    apr_sleep(RECONNECT_INTERVAL);
  }

  log_error(APLOG_MARK, APLOG_NOTICE, 0, server,
    "mod_log_gelf: Shutting down reconnection handler");
  apr_thread_exit(thd, APR_SUCCESS);

  return NULL;
}

static void log_gelf_child_init(apr_pool_t *p, server_rec *server) {
  apr_status_t rv;

  /* register cleanup function */
  apr_pool_cleanup_register(p, p, log_gelf_close_link, log_gelf_close_link);

  /* allocate memory for network sockets */
  apr_pool_create(&connection.socket_pool, p);
  
  /* start new thread to check server availability in TCP mode. Always send in UDP mode */
  if (config.protocol == TCP) {
    rv = apr_thread_create(&connection.reconnect_handler, NULL, log_gelf_check_tcp_port, server, p);
    if (rv != APR_SUCCESS) {
      log_error(APLOG_MARK, APLOG_ERR, 0, server,
        "mod_log_gelf: Can not create threat for reconnection handler");
    }
    rv = apr_thread_detach(connection.reconnect_handler);
    if (rv != APR_SUCCESS) {
      log_error(APLOG_MARK, APLOG_ERR, 0, server,
        "mod_log_gelf: Can not detach from reconnection handler");
    }
  } else {
    connection.reachable = 1;
    connection.connected = 1;
    log_gelf_get_socket(connection.socket_pool, server);
  }
}

apr_status_t log_gelf_close_link(void *p) {
  apr_status_t rv;

  /* exit reconnection thread */
  connection.shutdown = 1;

  /* close sockets */
  log_gelf_socket_close(connection.s);
  log_gelf_socket_close(connection.s_t);

  /* wait for thread to finish */
  apr_thread_join(&rv, connection.reconnect_handler);

  return APR_SUCCESS;
}

static void register_hooks(apr_pool_t *p) {
  ap_hook_post_config(log_gelf_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
  ap_hook_child_init(log_gelf_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(log_gelf_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA log_gelf_module = { 
    STANDARD20_MODULE_STUFF,
    NULL,                /* Per-directory configuration handler */
    NULL,                /* Merge handler for per-directory configurations */
    NULL,                /* Per-server configuration handler */
    NULL,                /* Merge handler for per-server configurations */
    log_gelf_directives, /* Any directives we may have for httpd */
    register_hooks       /* Our hook registering function */
};
