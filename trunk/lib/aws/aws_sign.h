#ifndef _AWS_SIGN_
#define _AWS_SIGN_

#include <stdint.h>

/**
 * aws_sign_s3_headers(key_id, key_secret, region, method, bucket, path,
 *     body, bodylen, x_amz_content_sha256, x_amz_date, authorization):
 * Return values ${x_amz_content_sha256}, ${x_amz_date}, and ${authorization}
 * such that
 *   ${method} ${path} HTTP/1.1
 *   Host: ${bucket}.s3.amazonaws.com
 *   X-Amz-Date: ${x_amz_date}
 *   X-Amz-Content-SHA256: ${x_amz_content_sha256}
 *   Authorization: ${authorization}
 * with the addition (if ${body} != NULL) of
 *   Content-Length: ${bodylen}
 *   <${body}>
 * is a correctly signed request to the ${region} S3 region.
 */
int aws_sign_s3_headers(const char *, const char *, const char *,
    const char *, const char *, const char *, const uint8_t *, size_t,
    char **, char **, char **);

/**
 * aws_sign_s3_querystr(key_id, key_secret, region, method, bucket, path,
 *     expiry):
 * Return a query string ${query} such that
 *   ${method} http://${bucket}.s3.amazonaws.com${path}?${query}
 * is a correctly signed request which expires in ${expiry} seconds, assuming
 * that the ${bucket} S3 bucket is in region ${region}.
 */
char * aws_sign_s3_querystr(const char *, const char *, const char *,
    const char *, const char *, const char *, int);

/**
 * aws_sign_ec2_headers(key_id, key_secret, region, body, bodylen,
 *     x_amz_content_sha256, x_amz_date, authorization):
 * Return values ${x_amz_content_sha256}, ${x_amz_date}, and ${authorization}
 * such that
 *     POST / HTTP/1.1
 *     Host: ec2.${region}.amazonaws.com
 *     X-Amz-Date: ${x_amz_date}
 *     X-Amz-Content-SHA256: ${x_amz_content_sha256}
 *     Authorization: ${authorization}
 *     Content-Length: ${bodylen}
 *     <${body}>
 * is a correctly signed request to the ${region} EC2 region.
 */
int aws_sign_ec2_headers(const char *, const char *, const char *,
    const uint8_t *, size_t, char **, char **, char **);

#endif /* !_AWS_SIGN_ */
