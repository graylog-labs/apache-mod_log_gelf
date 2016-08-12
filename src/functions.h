/* Begin the individual functions that, given a request r,
 * extract the needed information from it and return the
 * value to the calling entity.
 */

static const json_object *extract_remote_host(request_rec *r, char *a)
{
	return json_object_new_string(ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL));
}

static const json_object *extract_remote_address(request_rec *r, char *a) __attribute__((unused));

static const json_object *extract_remote_address(request_rec *r, char *a)
{
    #ifdef WITH_APACHE22
    return json_object_new_string(r->connection->remote_ip);
    #else
    return json_object_new_string(r->connection->client_ip);
    #endif
}

static const json_object *extract_local_address(request_rec *r, char *a) __attribute__((unused));

static const json_object *extract_local_address(request_rec *r, char *a)
{
    return json_object_new_string(r->connection->local_ip);
}

static const json_object *extract_remote_logname(request_rec *r, char *a)
{
  const char *rlogin = ap_get_remote_logname(r);
  if (rlogin == NULL) {
    return NULL;
  } else if (strlen(rlogin) == 0) {
    rlogin = "\"\"";
  }

	return json_object_new_string(rlogin);
}

static const json_object *extract_remote_user(request_rec *r, char *a)
{
	#ifdef WITH_APACHE13
	char *rvalue = r->connection->user;
	#else
	char *rvalue = r->user;
	#endif
	if (rvalue == NULL) {
		rvalue = "-";
	} else if (strlen(rvalue) == 0) {
		rvalue = "\"\"";
	}
	return json_object_new_string(rvalue);
}

static const json_object *extract_request_line(request_rec *r, char *a)
{
	/* Upddated to mod_log_config logic */
	/* NOTE: If the original request contained a password, we
	 * re-write the request line here to contain XXXXXX instead:
	 * (note the truncation before the protocol string for HTTP/0.9 requests)
	 * (note also that r->the_request contains the unmodified request)
	 */
	return json_object_new_string(
		    (r->parsed_uri.password)
				? apr_pstrcat(r->pool, r->method, " ",
					apr_uri_unparse(r->pool,
						&r->parsed_uri, 0),
					r->assbackwards ? NULL : " ",
					r->protocol, NULL)
				: r->the_request);
}

static const json_object *extract_request_file(request_rec *r, char *a)
{
	return json_object_new_string(r->filename);
}

static const json_object *extract_request_uri(request_rec *r, char *a)
{
	return json_object_new_string(r->uri);
}

static const json_object *extract_request_method(request_rec *r, char *a)
{
	return json_object_new_string(r->method);
}

static const json_object *extract_request_protocol(request_rec *r, char *a)
{
	return json_object_new_string(r->protocol);
}

static const json_object *extract_request_query(request_rec *r, char *a)
{
	return json_object_new_string((r->args) ? apr_pstrcat(r->pool, "?",
						r->args, NULL)
					 : "");
}

static const json_object *extract_status(request_rec *r, char *a)
{
	if (r->status <= 0) {
		return NULL;
	} else {
		return json_object_new_int(r->status);
	}
}

static const json_object *extract_virtual_host(request_rec *r, char *a)
{
    return json_object_new_string(r->server->server_hostname);
}

static const json_object *extract_server_name(request_rec *r, char *a)
{
    return json_object_new_string(ap_get_server_name(r));
}

static const json_object *extract_server_port(request_rec *r, char *a)
{
    return json_object_new_string(apr_psprintf(r->pool, "%u",
                        r->server->port ? r->server->port : ap_default_port(r)));
}

/* This respects the setting of UseCanonicalName so that
 * the dynamic mass virtual hosting trick works better.
 */
static const char *log_server_name(request_rec *r, char *a) __attribute__((unused));
static const char *log_server_name(request_rec *r, char *a)
{
    return ap_get_server_name(r);
}

static const json_object *extract_child_pid(request_rec *r, char *a)
{
    if (*a == '\0' || !strcmp(a, "pid")) {
        return json_object_new_string(apr_psprintf(r->pool, "%" APR_PID_T_FMT, getpid()));
    }
    else if (!strcmp(a, "tid")) {
#if APR_HAS_THREADS
        apr_os_thread_t tid = apr_os_thread_current();
#else
        int tid = 0; /* APR will format "0" anyway but an arg is needed */
#endif
        return json_object_new_string(apr_psprintf(r->pool, "%pT", &tid));
    }
    /* bogus format */
    return json_object_new_string(a);
}

static const json_object *extract_header(request_rec *r, char *a)
{
	const char *tempref;

	tempref = apr_table_get(r->headers_in, a);
	if (!tempref)
	{
		return NULL;
	} else {
		return json_object_new_string(tempref);
	}
}

static const json_object *extract_referer(request_rec *r, char *a)
{
	const char *tempref;

	tempref = apr_table_get(r->headers_in, "Referer");
	if (!tempref)
	{
		return NULL;
	} else {
		return json_object_new_string(tempref);
	}
}

static const json_object *extract_agent(request_rec *r, char *a)
{
    const char *tempag;

    tempag = apr_table_get(r->headers_in, "User-Agent");
    if (!tempag)
    {
        return NULL;
    } else {
        return json_object_new_string(tempag);
    }
}

static const json_object *extract_specific_cookie(request_rec *r, char *a)
{
  const char *cookiestr;
  char *cookieend;
	char *isvalid;
	char *cookiebuf;

	if (a != NULL) {
	  	log_error(APLOG_MARK,APLOG_DEBUG, 0, r->server,
			"watching for cookie '%s'", a);

		/* Fetch out the cookie header */
	 	cookiestr  = (char *)apr_table_get(r->headers_in,  "cookie2");
	    if (cookiestr != NULL) {
			log_error(APLOG_MARK,APLOG_DEBUG, 0, r->server,
				"Cookie2: [%s]", cookiestr);
			/* Does the cookie string contain one with our name? */
			isvalid = ap_strstr_c(cookiestr, a);
			if (isvalid != NULL) {
				/* Move past the cookie name and equal sign */
				isvalid += strlen(a) + 1;
				/* Duplicate it into the pool */
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
				/* Segregate just this cookie out of the string
				 * with a terminating nul at the first semicolon */
			    cookieend = ap_strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return json_object_new_string(cookiebuf);
			}
		}

	 	cookiestr  = (char *)apr_table_get(r->headers_in,  "cookie");
	    if (cookiestr != NULL) {
			log_error(APLOG_MARK,APLOG_DEBUG, 0, r->server,
				"Cookie: [%s]", cookiestr);
			isvalid = ap_strstr_c(cookiestr, a);
			if (isvalid != NULL) {
				isvalid += strlen(a) + 1;
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
			    cookieend = ap_strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return json_object_new_string(cookiebuf);
			}
		}

	 	cookiestr = apr_table_get(r->headers_out,  "set-cookie");
	    if (cookiestr != NULL) {
		     log_error(APLOG_MARK,APLOG_DEBUG, 0, r->server,
				"Set-Cookie: [%s]", cookiestr);
			isvalid = ap_strstr_c(cookiestr, a);
			if (isvalid != NULL) {
			    isvalid += strlen(a) + 1;
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
			    cookieend = ap_strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return json_object_new_string(cookiebuf);
			}
		}
	}

	return NULL;
}
