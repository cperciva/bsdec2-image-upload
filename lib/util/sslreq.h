#ifndef _SSLREQ_H_
#define _SSLREQ_H_

#include <stddef.h>

/**
 * sslreq2(host, port, certfile, req, reqlen, payload, plen, resp, resplen):
 * Establish an SSL connection to ${host}:${port}; verify the authenticity of
 * the server using certificates in ${certfile}; send ${reqlen} bytes from
 * ${req} and ${plen} bytes from ${payload}; and read a response of up to
 * ${*resplen} bytes into ${resp}.  Set ${*resplen} to the length of the
 * response read.  Return NULL on success or an error string.
 */
const char * sslreq2(const char *, const char *, const char *,
    const uint8_t *, int, const uint8_t *, size_t plen, uint8_t *, size_t *);

/* Backwards compat -- sslreq2 without a payload. */
#define sslreq(a, b, c, d, e, f, g) sslreq2(a, b, c, d, e, NULL, 0, f, g)

#endif /* !_SSLREQ_H_ */
