#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "sslreq.h"

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
	SSL * ssl;
	int readlen;
	size_t resppos;
	int on = 1;

	/* Create resolver hints structure. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	/* Perform DNS lookup. */
	if ((error = getaddrinfo(host, port, &hints, &res)) != 0)
		return "DNS lookup failed";

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
	if (r == NULL)
		return "Could not connect";

	/* Disable SIGPIPE on this socket. */
	if (setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)))
		return "Could not disable SIGPIPE";

	/* Launch SSL. */
	if (!SSL_library_init())
		return "Could not initialize SSL";

	/* Opt for compatibility. */
	if ((meth = SSLv23_client_method()) == NULL)
		return "Could not obtain SSL method";

	/* Create an SSL context. */
	if ((ctx = SSL_CTX_new((void *)(uintptr_t)(const void *)meth)) == NULL)
		return "Could not create SSL context";

	/* Disable SSLv2 and SSLv3. */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	/* We want blocking I/O; tell OpenSSL to keep trying reads/writes. */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	/* Load root certificates. */
	if (!SSL_CTX_load_verify_locations(ctx, certfile, NULL))
		return "Could not load root certificates";

	/* Create an SSL connection within the specified context. */
	if ((ssl = SSL_new(ctx)) == NULL)
		return "Could not create SSL connection";
	if (!SSL_set_fd(ssl, s))
		return "Could not attach SSL to socket";

	/* Enable SNI; some servers need this to send us the right cert. */
	if (!SSL_set_tlsext_host_name(ssl, host))
		return "Could not enable SNI";

	/* Tell OpenSSL which host we're trying to talk to... */
	if (!SSL_set1_host(ssl, host))
		return "SSL_set1_host failed";

	/* ... and ask it to make sure that this is what is happening. */
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

	/* Set ssl to work in client mode. */
	SSL_set_connect_state(ssl);

	/* Perform the SSL handshake. */
	if (SSL_connect(ssl) != 1)
		return "SSL handshake failed";

	/* Write our HTTP request. */
	if (SSL_write(ssl, req, reqlen) < reqlen)
		return "Could not write request";

	/* Write the payload. */
	if (payload && !SSL_write_ex(ssl, payload, plen, &plen))
		return "Could not write payload";

	/* Read the response. */
	for (resppos = 0; ; resppos += readlen) {
		if ((readlen = SSL_read(ssl, &resp[resppos], *resplen)) <= 0)
			break;
		*resplen -= readlen;
	}
	*resplen = resppos;

	/* Did the read fail? */
	if (readlen == -1)
		return "Could not read response";

	/* Shut down SSL. */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return (NULL);
}
