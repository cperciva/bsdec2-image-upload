#ifndef _SSLREQ_H_
#define _SSLREQ_H_

/**
 * sslreq(host, port, certfile, req, reqlen, resp, resplen):
 * Establish an SSL connection to ${host}:${port}; verify the authenticity of
 * the server using certificates in ${certfile}; send ${reqlen} bytes from
 * ${req}; and read a response of up to ${*resplen} bytes into ${resp}.  Set
 * ${*resplen} to the length of the response read.  Return NULL on success or
 * an error string.
 */
const char * sslreq(const char *, const char *, const char *,
    const uint8_t *, int, uint8_t *, size_t *);

#endif /* !_SSLREQ_H_ */
