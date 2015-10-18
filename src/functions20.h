static const char *extract_bytes_sent(request_rec *r, char *a)
{
	if (!r->sent_bodyct || !r->bytes_sent) {
		return "-";
	} else {
		return apr_psprintf(r->pool, "%" APR_OFF_T_FMT, r->bytes_sent);
	}
}

static const char *extract_request_time_custom(request_rec *r, char *a,
                                           apr_time_exp_t *xt)
{
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_strftime(tstr, &retcode, sizeof(tstr), a, xt);
    return apr_pstrdup(r->pool, tstr);
}

#define DEFAULT_REQUEST_TIME_SIZE 32
typedef struct {
    unsigned t;
    char timestr[DEFAULT_REQUEST_TIME_SIZE];
    unsigned t_validate;
} cached_request_time;

#define TIME_CACHE_SIZE 4
#define TIME_CACHE_MASK 3
static cached_request_time request_time_cache[TIME_CACHE_SIZE];

static const char *extract_request_time(request_rec *r, char *a)
{
	apr_time_exp_t xt;

	/* Please read comments in mod_log_config.h for more info about
	 * the I_INSIST....COMPLIANCE define
	 */
	if (a && *a) {     /* Custom format */
#ifdef I_INSIST_ON_EXTRA_CYCLES_FOR_CLF_COMPLIANCE
        ap_explode_recent_localtime(&xt, apr_time_now());
#else
        ap_explode_recent_localtime(&xt, r->request_time);
#endif
        return extract_request_time_custom(r, a, &xt);
	} else {		   /* CLF format */
        /* This code uses the same technique as ap_explode_recent_localtime():
         * optimistic caching with logic to detect and correct race conditions.
         * See the comments in server/util_time.c for more information.
         */
        cached_request_time* cached_time = apr_palloc(r->pool,
                                                      sizeof(*cached_time));
#ifdef I_INSIST_ON_EXTRA_CYCLES_FOR_CLF_COMPLIANCE
        apr_time_t request_time = apr_time_now();
#else
        apr_time_t request_time = r->request_time;
#endif
        unsigned t_seconds = (unsigned)apr_time_sec(request_time);
        unsigned i = t_seconds & TIME_CACHE_MASK;
        memcpy(cached_time, &(request_time_cache[i]), sizeof(*cached_time));
        if ((t_seconds != cached_time->t) ||
            (t_seconds != cached_time->t_validate)) {

            /* Invalid or old snapshot, so compute the proper time string
             * and store it in the cache
             */
            char sign;
            int timz;

            ap_explode_recent_localtime(&xt, r->request_time);
            timz = xt.tm_gmtoff;
            if (timz < 0) {
                timz = -timz;
                sign = '-';
            }
            else {
                sign = '+';
            }
            cached_time->t = t_seconds;
            apr_snprintf(cached_time->timestr, DEFAULT_REQUEST_TIME_SIZE,
                         "%d-%02d-%02dT%02d:%02d:%02d",
                         xt.tm_year+1900, xt.tm_mon+1, xt.tm_mday,
                         xt.tm_hour, xt.tm_min, xt.tm_sec);
            cached_time->t_validate = t_seconds;
            memcpy(&(request_time_cache[i]), cached_time,
                   sizeof(*cached_time));
		}
		return cached_time->timestr;
	}
}

static const char *extract_request_duration(request_rec *r, char *a)
{
	apr_time_t duration = apr_time_now() - r->request_time;
	return apr_psprintf(r->pool, "%.3lf", apr_time_usec(duration)/1000.0);
}

static const char *extract_request_timestamp(request_rec *r, char *a)
{
	return apr_psprintf(r->pool, "%"APR_TIME_T_FMT, apr_time_sec(apr_time_now()));
}

static const char *extract_connection_status(request_rec *r, char *a) __attribute__((unused));
static const char *extract_connection_status(request_rec *r, char *a)
{
    if (r->connection->aborted)
        return "X";

    if (r->connection->keepalive == AP_CONN_KEEPALIVE &&
        (!r->server->keep_alive_max ||
         (r->server->keep_alive_max - r->connection->keepalives) > 0)) {
        return "+";
    }
    return "-";
}
