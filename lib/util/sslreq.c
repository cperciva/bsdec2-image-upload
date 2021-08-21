#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <assert.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "sslreq.h"

/*
 * LibreSSL claims to be OpenSSL 2.0, but (mostly) has APIs compatible with
 * OpenSSL 1.0.1g.
 */
#ifdef LIBRESSL_VERSION_NUMBER
#undef OPENSSL_VERSION_NUMBER
#define OPENSSL_VERSION_NUMBER 0x1000107fL
#if LIBRESSL_VERSION_NUMBER >= 0x2090000fL
#define HAVE_SSL_SET1_HOST
#endif
#if LIBRESSL_VERSION_NUMBER >= 0x3030200fL
#define HAVE_SSL_SET_HOSTFLAGS
#endif
#endif

/* Compatibility for OpenSSL pre-1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef HAVE_SSL_SET1_HOST
static int
SSL_set1_host(SSL * ssl, const char * hostname)
{
	X509_VERIFY_PARAM * param;

	param = SSL_get0_param(ssl);
	return (X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname)));
}
#endif

#ifndef HAVE_SSL_SET_HOSTFLAGS
static void
SSL_set_hostflags(SSL * ssl, unsigned int flags)
{
	X509_VERIFY_PARAM * param;

	param = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set_hostflags(param, flags);
}
#endif
#endif

/* Compatibility for OpenSSL pre-1.1.1. */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
static int
SSL_write_ex(SSL * ssl, const void * buf, size_t num,
    size_t * written)
{
	int towrite;
	int ret;

	/* Sanity check. */
	assert(num > 0);

	/* Nothing written yet. */

	/* Loop until we've written everything. */
	while(1) {
		if (num > INT_MAX)
			towrite = INT_MAX;
		else
			towrite = num;

		/* Attempt to send data. */
		ret = SSL_write(ssl, buf, towrite);
		if (ret > 0) {
			/* Sanity check. */
			assert(ret <= towrite);

			/* Record the number of bytes written. */
			*written += (size_t)ret;
			buf = (const uint8_t *)(buf) + (size_t)ret;
			num -= (size_t)ret;

			/* Are we finished? */
			if (num == 0) {
				ret = 1;
				break;
			}

			/* Write some more. */
			continue;
		} else {
			/*
			 * Do nothing here, because ret is a meaningful value for
			 * determining the error.
			 */
			break;
		}
	}

	return (ret);
}
#endif

/**
 * sslreq2(host, port, certfile, req, reqlen, payload, plen, resp, resplen):
 * Establish an SSL connection to ${host}:${port}; verify the authenticity of
 * the server using certificates in ${certfile}; send ${reqlen} bytes from
 * ${req} and ${plen} bytes from ${payload}; and read a response of up to
 * ${*resplen} bytes into ${resp}.  Set ${*resplen} to the length of the
 * response read.  Return NULL on success or an error string.
 */
const char *
sslreq2(const char * host, const char * port, const char * certfile,
    const uint8_t * req, int reqlen, const uint8_t * payload, size_t plen,
    uint8_t * resp, size_t * resplen)
{
	struct addrinfo hints;
	struct addrinfo * res;
	struct addrinfo * r;
	int error;
	int s;
	const SSL_METHOD * meth;
	SSL_CTX * ctx;
	BIO * b;
	SSL * ssl;
	int readlen;
	size_t resppos;
	const char * errstr = NULL;

	/* Create resolver hints structure. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	/* Perform DNS lookup. */
	if ((error = getaddrinfo(host, port, &hints, &res)) != 0) {
		errstr = "DNS lookup failed";
		goto out0;
	}

	/* Iterate through the addresses we obtained trying to connect. */
	for (r = res; r != NULL; r = r->ai_next) {
		/* Create a socket. */
		if ((s = socket(r->ai_family, r->ai_socktype, 0)) == -1)
			continue;

		/* Attempt to connect. */
		if (connect(s, r->ai_addr, r->ai_addrlen) == 0)
			break;

		/* Close the socket; this address didn't work. */
		close(s);
	}

	/* Free the addresses. */
	freeaddrinfo(res);

	/* Did we manage to connect? */
	if (r == NULL) {
		errstr = "Could not connect";
		goto out0;
	}

	/* Launch SSL. */
	if (!SSL_library_init()) {
		errstr = "Could not initialize SSL";
		close(s);
		goto out0;
	}

	/* Opt for compatibility. */
	if ((meth = SSLv23_client_method()) == NULL) {
		errstr = "Could not obtain SSL method";
		close(s);
		goto out0;
	}

	/* Create an SSL context. */
	if ((ctx =
	    SSL_CTX_new((void *)(uintptr_t)(const void *)meth)) == NULL) {
		errstr = "Could not create SSL context";
		close(s);
		goto out0;
	}

	/* Disable SSLv2 and SSLv3. */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	/* We want blocking I/O; tell OpenSSL to keep trying reads/writes. */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	/* Load root certificates. */
	if (certfile) {
		if (!SSL_CTX_load_verify_locations(ctx, certfile, NULL)) {
			errstr = "Could not load root certificates";
			close(s);
			goto out1;
		}
	} else {
		if (!SSL_CTX_set_default_verify_paths(ctx)) {
			errstr = "Could not load root certificates";
			close(s);
			goto out1;
		}
	}

	/* Create an SSL connection within the specified context. */
	if ((ssl = SSL_new(ctx)) == NULL) {
		errstr = "Could not create SSL connection";
		close(s);
		goto out1;
	}

	/* Attach the socket we opened earlier. */
	if ((b = BIO_new_socket(s, 1)) == NULL) {
		errstr = "Could not create BIO";
		close(s);
		goto out2;
	}
	SSL_set_bio(ssl, b, b);

	/* Enable SNI; some servers need this to send us the right cert. */
	if (!SSL_set_tlsext_host_name(ssl, host)) {
		errstr = "Could not enable SNI";
		goto out2;
	}

	/* Tell OpenSSL which host we're trying to talk to... */
	if (!SSL_set1_host(ssl, host)) {
		errstr = "SSL_set1_host failed";
		goto out2;
	}

	/* ... and ask it to make sure that this is what is happening. */
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

	/* Set ssl to work in client mode. */
	SSL_set_connect_state(ssl);

	/* Perform the SSL handshake. */
	if (SSL_connect(ssl) != 1) {
		errstr = "SSL handshake failed";
		goto out2;
	}

	/* Write our HTTP request. */
	if (SSL_write(ssl, req, reqlen) < reqlen) {
		errstr = "Could not write request";
		goto out3;
	}

	/* Write the payload. */
	if (payload && !SSL_write_ex(ssl, payload, plen, &plen)) {
		errstr = "Could not write payload";
		goto out3;
	}

	/* Read the response. */
	for (resppos = 0; ; resppos += readlen) {
		if ((readlen = SSL_read(ssl, &resp[resppos], *resplen)) <= 0)
			break;
		*resplen -= readlen;
	}
	*resplen = resppos;

	/* Did the read fail? */
	if (readlen == -1) {
		errstr = "Could not read response";
		goto out3;
	}

	/* Shut down SSL. */
out3:
	SSL_shutdown(ssl);
out2:
	SSL_free(ssl);
out1:
	SSL_CTX_free(ctx);
out0:
	return (errstr);
}
