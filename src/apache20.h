#ifndef APACHE20_H
#define APACHE20_H

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_reslist.h"
#include "apr_signal.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_tables.h"

#include "ap_config.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include "util_time.h"

#define log_error ap_log_error

#endif /* APACHE20_H */
