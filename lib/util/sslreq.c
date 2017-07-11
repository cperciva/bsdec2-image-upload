#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "sslreq.h"

/**
 * sslreq(host, port, certfile, req, reqlen, resp, resplen):
 * Establish an SSL connection to ${host}:${port}; verify the authenticity of
 * the server using certificates in ${certfile}; send ${reqlen} bytes from
 * ${req}; and read a response of up to ${*resplen} bytes into ${resp}.  Set
 * ${*resplen} to the length of the response read.  Return NULL on success or
 * an error string.
 */
const char *
sslreq(const char * host, const char * port, const char * certfile,
    const uint8_t * req, int reqlen, uint8_t * resp, size_t * resplen)
{
	struct addrinfo hints;
	struct addrinfo * res;
	struct addrinfo * r;
	int error;
	int s;
	const SSL_METHOD * meth;
	SSL_CTX * ctx;
	SSL * ssl;
	X509 * cert;
	X509_NAME * name;
	char hostname[256];
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

	/* Perform the SSL handshake. */
	if (SSL_connect(ssl) != 1)
		return "SSL handshake failed";

	/* Make sure the server's certificate is valid. */
	if (SSL_get_verify_result(ssl) != X509_V_OK)
		return "Could not verify server SSL certificate";

	/* Get the server's certificate. */
	if ((cert = SSL_get_peer_certificate(ssl)) == NULL)
		return "Could not get server SSL certificate";

	/* Extract the name. */
	if ((name = X509_get_subject_name(cert)) == NULL)
		return "Could not extract subject name from certificate";
	if (!X509_NAME_get_text_by_NID(name, NID_commonName, hostname, 256))
		return "Could not extract CN from certificate";

	/* Does the name match? */
	if (strcasecmp(hostname, host) &&
	    ((hostname[0] != '*') || (hostname[1] != '.') ||
	    strcasecmp(&hostname[2], host)))
		return "Name on SSL certificate does not match server";

	/* Write our HTTP request. */
	if (SSL_write(ssl, req, reqlen) < reqlen)
		return "Could not write request";

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
