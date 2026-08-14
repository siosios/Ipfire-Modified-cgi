/*#############################################################################
#                                                                             #
# zone-sync - A tool to keep DNS zone files in sync                           #
# Copyright (C) 2026 IPFire Development Team                                  #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
#############################################################################*/

#include <argp.h>
#include <netdb.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <urcu/rculist.h>
#include <urcu/wfcqueue.h>
#include <urcu/call-rcu.h>

#include <dns/dispatch.h>
#include <dns/name.h>
#include <dns/view.h>
#include <dns/xfrin.h>
#include <dns/zone.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/tls.h>

#define DEFAULT_PATH	LOCALSTATEDIR "/lib/zone-sync"

#define MAX_ZONES		128

typedef struct zone_ctx {
	const char* name;
	dns_zone_t* zone;
	dns_xfrin_t* xfrin;
} zone_ctx;

typedef struct ctx {
	// Log Level
	int log_level;

	// Return Code
	int rc;

	// Path
	const char* path;

	// Parallel
	unsigned long parallel;

	// Flags
	enum {
		SECURE = (1 << 0),
	} flags;

	// Primary
	const char* primary;
	isc_sockaddr_t primary_address;

	// Source
	isc_sockaddr_t source_address;

	// Transport
	dns_transport_list_t* transports;
	dns_transport_t* transport;

	// Zones
	zone_ctx zones[MAX_ZONES];
	unsigned int num_zones;

	// How many transfers are running?
	unsigned long running;
	unsigned long processed;

	// Memory Context
	isc_mem_t* memctx;

	// Logging
	isc_log_t* log;

	// Loop Manager
	isc_loopmgr_t* loopmgr;

	// Network Manager
	isc_nm_t* netmgr;

	// Zone Manager
	dns_zonemgr_t* zonemgr;

	// Dispatch Manager
	dns_dispatchmgr_t* dispatchmgr;

	// View
	dns_view_t* view;

	// TLS Context Cache
	isc_tlsctx_cache_t* tlsctx_cache;
} ctx_t;

// Create the context
static ctx_t ctx = {
	.log_level = LOG_INFO,
	.parallel  = 1,
	.path      = DEFAULT_PATH,
	.transport = DNS_TRANSPORT_NONE,
};

static dns_fixedname_t fixed = {};

static void logger(int priority, const char* format, ...)
	__attribute__((format(printf, 2, 3)));

static void logger(int priority, const char* format, ...) {
	char buffer[4096];
	FILE* f = NULL;
	ssize_t length;
	va_list args;

	// Don't log if below log level
	if (priority > ctx.log_level)
		return;

	// Format the log message
	va_start(args, format);
	length = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	// Fail if we could not format the string
	if (length < 0)
		return;

	// Select the output stream
	switch (priority) {
		case LOG_ERR:
			f = stderr;
			break;

		default:
			f = stdout;
			break;
	}

	// Write to the output stream
	fwrite(buffer, 1, length, f);
}

// Logging functions
#define INFO(...) logger(LOG_INFO, __VA_ARGS__)
#define ERROR(...) logger(LOG_ERR, __VA_ARGS__)
#define DEBUG(...) logger(LOG_DEBUG, __VA_ARGS__)

static void setup_logging(void) {
	isc_logconfig_t *logcfg = NULL;
	int level = ISC_LOG_INFO;

	/* Create the log context and a default config */
	isc_log_create(ctx.memctx, &ctx.log, &logcfg);

	// Translate the log level
	switch (ctx.log_level) {
		case LOG_DEBUG:
			level = ISC_LOG_DEBUG(6);
			break;

		case LOG_ERR:
			level = ISC_LOG_ERROR;
			break;
	}

	/* Define a channel that writes everything to stderr */
	isc_logdestination_t dest = {
		.file = {
			.stream = stderr,
			.name = NULL,
			.versions = 0,
			.maximum_size = 0,
		},
	};
	isc_log_createchannel(
		logcfg,
		"stderr",                       /* channel name */
		ISC_LOG_TOFILEDESC,             /* destination type */
		level,
		&dest,
		0);

	/* Attach the channel to ALL categories/modules
	* (NULL category = wildcard, NULL module = wildcard) */
	isc_log_usechannel(logcfg, "stderr", NULL, NULL);

	// Set this as the default log context
	isc_log_setcontext(ctx.log);
	dns_log_setcontext(ctx.log);
}

static isc_result_t dns_name_from_string(dns_name_t** name, const char *text) {
	isc_buffer_t buffer = {};
	dns_name_t* n = NULL;
	int r;

	// Allocate some memory
	n = dns_fixedname_initname(&fixed);

	// Determine the length of the input
	size_t l = strlen(text);

	// Add the name to the buffer
	isc_buffer_constinit(&buffer, text, l);
	isc_buffer_add(&buffer, l);

	// Create a new dns_name_t object from the buffer
	r = dns_name_fromtext(n, &buffer, dns_rootname, 0, NULL);
	if (r)
		return r;

	// Return the name
	*name = n;

	return 0;
}

// Returns the zone context for a given zone
static zone_ctx* find_zone(dns_zone_t* z) {
	for (unsigned int i = 0; i < ctx.num_zones; i++) {
		if (ctx.zones[i].zone == z)
			return &ctx.zones[i];
	}

	return NULL;
}

static int do_work(void);

static void maybe_shutdown(void) {
	// Don't shut down if there is something left running
	if (ctx.running)
		return;

	DEBUG("Shutting down...\n");

	if (ctx.loopmgr)
		isc_loopmgr_shutdown(ctx.loopmgr);
}

static void zone_done(dns_zone_t* z) {
	// Fetch the zone
	zone_ctx* zone = find_zone(z);
	if (!zone)
		return;

	// Detach the XFR object
	if (zone->xfrin)
		dns_xfrin_detach(&zone->xfrin);

	// Release the zone from the manager
	dns_zonemgr_releasezone(ctx.zonemgr, zone->zone);

	// Free the zone
	dns_zone_detach(&zone->zone);

	// Decrement the number of running zones
	ctx.running--;

	// Launch some more work
	do_work();

	// Terminate if we are all done
	maybe_shutdown();
}

static void transfer_done(dns_zone_t* zone, uint32_t* expireopt, isc_result_t result) {
	char name[DNS_NAME_FORMATSIZE];
	dns_name_t* origin = NULL;
	int r;

	// Fetch the origin
	origin = dns_zone_getorigin(zone);

	// Extract the name
	dns_name_format(origin, name, sizeof(name));

	switch (result) {
		case ISC_R_SUCCESS:
			INFO("%s: Transfer successful\n", name);

			// Commit any changes
			r = dns_zone_dump(zone);
			if (r) {
				ERROR("%s: Failed to flush zone\n", name);
				ctx.rc = 1;
			}
			break;

		case DNS_R_UPTODATE:
			INFO("%s: Zone is up to date\n", name);
			break;

		default:
			ERROR("%s: Zone transfer failed\n", name);
			ctx.rc = 1;
			break;
	}

	// We are done
	zone_done(zone);
}


static int do_transfer(zone_ctx* zone, uint32_t serial) {
	dns_rdatatype_t xfrtype;
	int r;

	// Try an incremental xfr if we have a serial
	if (serial) {
		DEBUG("Zone is at serial %u, trying IXFR\n", serial);
		xfrtype = dns_rdatatype_soa;

	// Otherwise force AXFR
	} else {
		DEBUG("No serial for zone, doing AXFR\n");
		xfrtype = dns_rdatatype_axfr;
	}

	// Require at least 10 kBit/s to be transmitted over 5 minutes
	dns_zone_setminxfrratein(zone->zone, 10240, 300);

	dns_xfrin_create(zone->zone, xfrtype, &ctx.primary_address, &ctx.source_address, NULL,
		DNS_TRANSPORT_NONE, ctx.transport, ctx.tlsctx_cache, ctx.memctx, &zone->xfrin);

	// Start the transfer
	r = dns_xfrin_start(zone->xfrin, transfer_done);
	switch (r) {
		case ISC_R_SUCCESS:
			break;

		default:
			ERROR("Failed to initialize zone transfer: %s\n", isc_result_totext(r));
			ctx.rc = 1;
			goto ERROR;
	}

	return r;

ERROR:
	zone_done(zone->zone);
	return r;
}

static isc_result_t zone_loaded(void* data) {
	zone_ctx* zone = data;
	uint32_t serial = 0;
	int r;

	// Fetch the serial
	r = dns_zone_getserial(zone->zone, &serial);
	switch (r) {
		case ISC_R_SUCCESS:
			DEBUG("Zone loaded from %s with serial %u\n",
				dns_zone_getfile(zone->zone), serial);
			break;

		case DNS_R_NOTLOADED:
			DEBUG("Could not load zone from %s\n",
				dns_zone_getfile(zone->zone));
			break;

		default:
			ERROR("Failed to load zone from %s\n",
				dns_zone_getfile(zone->zone));
			goto ERROR;
	}

	// Initiate the transfer
	return do_transfer(zone, serial);

ERROR:
	// Destroy the zone
	zone_done(zone->zone);

	return r;
}

static void do_zone(zone_ctx* zone) {
	dns_name_t* origin = NULL;
	char journal_path[PATH_MAX];
	char path[PATH_MAX];
	int r;

	// Increment counter
	ctx.running++;

	// Create the origin
	r = dns_name_from_string(&origin, zone->name);
	if (r)
		goto ERROR;

	DEBUG("Processing zone %s\n", zone->name);

	// Compose the path for the zone
	r = snprintf(path, sizeof(path), "%s/%s.zone", ctx.path, zone->name);
	if (r < 0) {
		ERROR("Failed to make path to zone: %m\n");
		goto ERROR;
	}

	// Compose the path of the journal
	r = snprintf(journal_path, sizeof(journal_path), "%s.jnl", path);
	if (r < 0) {
		ERROR("Failed to make path for the journal: %m\n");
		goto ERROR;
	}

	// Create a new zone
	dns_zone_create(&zone->zone, ctx.memctx, 0);

	// Manage the zone through the zone manager
	r = dns_zonemgr_managezone(ctx.zonemgr, zone->zone);
	if (r) {
		ERROR("Failed to add the zone to the zone manager: %s\n", isc_result_totext(r));
		ctx.rc = 1;
		goto ERROR;
	}

	// Set the zone's origin
	r = dns_zone_setorigin(zone->zone, origin);
	if (r) {
		ERROR("Failed to set the zone's origin\n");
		ctx.rc = 1;
		goto ERROR;
	}

	// We treat this as a secondary zone
	dns_zone_settype(zone->zone, dns_zone_secondary);

	// Set the class
	dns_zone_setclass(zone->zone, dns_rdataclass_in);

	// Set the filename of the zone
	r = dns_zone_setfile(zone->zone, path, dns_masterformat_text, &dns_master_style_default);
	if (r) {
		ERROR("Failed to set the zone's filename %s: %m\n", path);
		ctx.rc = 1;
		goto ERROR;
	}

	// Set the path of the journal
	r = dns_zone_setjournal(zone->zone, journal_path);
	if (r) {
		ERROR("Failed to set the zone's journal path: %s\n", isc_result_totext(r));
		ctx.rc = 1;
		goto ERROR;
	}

	// Attach view to the zone
	dns_zone_setview(zone->zone, ctx.view);

	// Load the zone from file
	r = dns_zone_asyncload(zone->zone, 0, zone_loaded, zone);
	switch (r) {
		case ISC_R_SUCCESS:
			break;

		default:
			ERROR("Failed to load zone: %s\n", isc_result_totext(r));
			ctx.rc = 1;
			goto ERROR;
	}

	// Done
	return;

ERROR:
	// Destroy the zone
	zone_done(zone->zone);
}

/*
	Called to start some more work to do
*/
static int do_work(void) {
	while (!ctx.parallel || (ctx.running < ctx.parallel)) {
		// We are done if all zones have been processed
		if (ctx.processed >= ctx.num_zones)
			break;

		// Launch the next zone
		do_zone(&ctx.zones[ctx.processed++]);
	}

	return 0;
}

static int configure_transports(void) {
	dns_transport_type_t type = DNS_TRANSPORT_TCP;
	dns_name_t* name = NULL;
	int r;

	// Use the name of the primary
	r = dns_name_from_string(&name, ctx.primary);
	if (r) {
		ERROR("Failed to parse the transport name %s: %s\n",
			ctx.primary, isc_result_totext(r));
		return r;
	}

	// Enable TLS if secure transport is requested
	if (ctx.flags & SECURE)
		type = DNS_TRANSPORT_TLS;

	// Allocate a new transport list
	ctx.transports = dns_transport_list_new(ctx.memctx);

	// Allocate a new transport
	ctx.transport = dns_transport_new(name, type, ctx.transports);

	// Set the remote hostname (for TLS SNI)
	switch (type) {
		case DNS_TRANSPORT_TLS:
			dns_transport_set_remote_hostname(ctx.transport, ctx.primary);
			dns_transport_set_tlsname(ctx.transport, ctx.primary);
			break;

		default:
			break;
	}

	return 0;
}

static void run_loop(void* data) {
	struct in_addr any = {
		.s_addr = INADDR_ANY,
	};
	int r;

	DEBUG("Event loop started\n");

	// Create a new dispatch manager
	dns_dispatchmgr_create(ctx.memctx, ctx.loopmgr, ctx.netmgr, &ctx.dispatchmgr);

	// Create a zone manager
	dns_zonemgr_create(ctx.memctx, ctx.netmgr, &ctx.zonemgr);

	// Create the source address
	isc_sockaddr_fromin(&ctx.source_address, &any, 0);

	// Configure transports
	r = configure_transports();
	if (r)
		goto ERROR;

	// Create a view
	r = dns_view_create(ctx.memctx, ctx.loopmgr, ctx.dispatchmgr,
			dns_rdataclass_in, "default", &ctx.view);
	if (r) {
		ERROR("Failed to create view: %s\n", isc_result_totext(r));
		goto ERROR;
	}

	// Do some work
	do_work();

ERROR:
	// Potentially shut down if there is nothing to do
	maybe_shutdown();

	// Done
	return;
}

static void destroy_loop(void* data) {
	DEBUG("Destroying event loop\n");

	// Destroy the view
	if (ctx.view)
		dns_view_detach(&ctx.view);

	// Destroy the transport list
	if (ctx.transports)
		dns_transport_list_detach(&ctx.transports);

	// Destroy the zone manager
	if (ctx.zonemgr) {
		dns_zonemgr_shutdown(ctx.zonemgr);
		dns_zonemgr_detach(&ctx.zonemgr);
	}

	// Detach the dispatch manager
	if (ctx.dispatchmgr)
		dns_dispatchmgr_detach(&ctx.dispatchmgr);
}

const char* argp_program_version = PACKAGE_VERSION;

static const char* args_doc = "ZONE [ZONE...]";

enum {
	OPT_DEBUG    = 1,
	OPT_QUIET    = 2,
	OPT_PATH     = 3,
	OPT_PARALLEL = 4,
	OPT_PRIMARY  = 5,
	OPT_SECURE   = 6,
};

static struct argp_option options[] = {
	{ "debug",    OPT_DEBUG,    NULL,       0, "Run in debug mode", 0 },
	{ "quiet",    OPT_QUIET,    NULL,       0, "Run in quiet mode", 0 },
	{ "path",     OPT_PATH,     "PATH",     1, "Path where to store the zones", 0 },
	{ "parallel", OPT_PARALLEL, "N",        1, "How many zones to process simultaneously", 0 },
	{ "primary",  OPT_PRIMARY,  "HOSTNAME", 1, "The hostname of the primary to fetch from", 0 },
	{ "secure",   OPT_SECURE ,  NULL,       0, "Use a secure transport to transfer the zone", 0 },
	{ NULL },
};

static int resolve_primary(void) {
	struct addrinfo* res = NULL;
	uint32_t port = 53;
	int r;

	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	// Enable TLS?
	if (ctx.flags & SECURE)
		port = 853;

	// Resolve
	r = getaddrinfo(ctx.primary, "53", &hints, &res);
	if (r)
		goto ERROR;

	// Parse the response
	switch (res->ai_family) {
		case AF_INET6:
			isc_sockaddr_fromin6(&ctx.primary_address,
				&((struct sockaddr_in6*)res->ai_addr)->sin6_addr, port);
			break;

		case AF_INET:
			isc_sockaddr_fromin(&ctx.primary_address,
				&((struct sockaddr_in*)res->ai_addr)->sin_addr, port);
			break;

		default:
			abort();
	}

ERROR:
	if (res)
		freeaddrinfo(res);

	return r;
}

static error_t parse(int key, char* arg, struct argp_state* state) {
	char* e = NULL;
	int r;

	switch (key) {
		case OPT_DEBUG:
			ctx.log_level = LOG_DEBUG;
			break;

		case OPT_QUIET:
			ctx.log_level = LOG_ERR;
			break;

		case OPT_PATH:
			ctx.path = arg;
			break;

		case OPT_PRIMARY:
			ctx.primary = arg;
			break;

		case OPT_PARALLEL:
			// Parse the number
			ctx.parallel = strtoul(arg, &e, 10);

			// Check if we could parse the number
			if ((e && *e) || (ctx.parallel == ULONG_MAX)) {
				argp_failure(state, EXIT_FAILURE, 0, "Could not parse number: %s", arg);
				return ARGP_ERR_UNKNOWN;
			}
			break;

		case OPT_SECURE:
			ctx.flags |= SECURE;
			break;

		case ARGP_KEY_ARG:
			// Check if we have too many zones
			if (ctx.num_zones >= MAX_ZONES) {
				argp_failure(state, EXIT_FAILURE, 0, "Too many zones");
				return ARGP_ERR_UNKNOWN;
			}

			// Store the name of the zone
			ctx.zones[ctx.num_zones++].name = arg;
			break;

		case ARGP_KEY_SUCCESS:
			// Fail if we don't have any zones
			if (!ctx.num_zones) {
				argp_failure(state, EXIT_FAILURE, 0, "You must pass a zone");
			}

			// Resolve the primary
			if (ctx.primary) {
				r = resolve_primary();
				if (r)
					argp_failure(state, EXIT_FAILURE, 0,
							"Failed to resolve %s: %s", ctx.primary, gai_strerror(r));

			// Fail if we don't have a primary
			} else {
				argp_failure(state, EXIT_FAILURE, 0, "You must pass a primary");
			}

			break;

		// Ignore these
		case ARGP_KEY_END:
		case ARGP_KEY_ERROR:
		case ARGP_KEY_INIT:
		case ARGP_KEY_FINI:
			break;

		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main(int argc, char* argv[]) {
	int r;

	// Setup the command line parser
	struct argp parser = {
		.options   = options,
		.parser    = parse,
		.args_doc  = args_doc,
	};
	int arg_index = 0;

	// Parse the command line
	r = argp_parse(&parser, argc, argv, ARGP_IN_ORDER, &arg_index, NULL);
	if (r)
		goto ERROR;

	// Allocate a new memory context
	isc_mem_create(&ctx.memctx);

	// Setup logging
	setup_logging();

	// Create the TLS context cache
	isc_tlsctx_cache_create(ctx.memctx, &ctx.tlsctx_cache);

	// Initialize the loop manager
	isc_loopmgr_create(ctx.memctx, 1, &ctx.loopmgr);

	// Create a new netmgr
	isc_netmgr_create(ctx.memctx, ctx.loopmgr, &ctx.netmgr);

	// Register a callback to be called when the loop starts/finishes
	isc_loopmgr_setup(ctx.loopmgr, run_loop, &ctx);
	isc_loopmgr_teardown(ctx.loopmgr, destroy_loop, &ctx);

	// Run the event loop
	isc_loopmgr_run(ctx.loopmgr);

ERROR:
	if (ctx.netmgr)
		isc_netmgr_destroy(&ctx.netmgr);
	if (ctx.loopmgr)
		isc_loopmgr_destroy(&ctx.loopmgr);
	if (ctx.tlsctx_cache)
		isc_tlsctx_cache_detach(&ctx.tlsctx_cache);

	// Exit with our local return code if set
	if (r)
		return r;

	// Otherwise we use the global return code
	// that could have been set in any of the callbacks.
	return ctx.rc;
}
