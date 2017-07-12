#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asprintf.h"
#include "aws_sign.h"
#include "elasticarray.h"
#include "entropy.h"
#include "hexify.h"
#include "rfc3986.h"
#include "sslreq.h"
#include "warnp.h"

#define CERTFILE "/usr/local/share/certs/ca-root-nss.crt"
#define PARTSZ (10 * 1024 * 1024)

/* Elastic string type. */
ELASTICARRAY_DECL(STR, str, char);

/* Elastic array of strings. */
ELASTICARRAY_DECL(STRARRAY, strarray, char *);

static char *
encodeamp(char * s)
{
	size_t len, i, j;
	char * t;

	/* Compute length of escaped string. */
	for (len = i = 0; s[i] != '\0'; i++) {
		if (s[i] == '&')
			len += 5;
		else
			len += 1;
	}

	/* Allocate new string. */
	if ((t = malloc(len + 1)) == NULL)
		goto done;

	/* Copy bytes across, escaping '&' when needed. */
	for (i = j = 0; s[i] != '\0'; i++) {
		if (s[i] == '&') {
			memcpy(&t[j], "&amp;", 5);
			j += 5;
		} else {
			t[j] = s[i];
			j += 1;
		}
	}
	t[j] = '\0';

done:
	/* Free the old string. */
	free(s);

	/* Return our new string (or NULL if malloc failed). */
	return (t);
}

static int
readkeys(const char * fname, char ** key_id, char ** key_secret)
{
	FILE * f;
	char buf[1024];
	char * p;

	/* No keys yet. */
	*key_id = *key_secret = NULL;

	/* Open the key file. */
	if ((f = fopen(fname, "r")) == NULL) {
		warnp("fopen(%s)", fname);
		goto err0;
	}

	/* Read lines of up to 1024 characters. */
	while (fgets(buf, sizeof(buf), f) != NULL) {
		/* Find the first EOL character and truncate. */
		p = buf + strcspn(buf, "\r\n");
		if (*p == '\0') {
			warn0("Missing EOL in %s", fname);
			break;
		} else
			*p = '\0';

		/* Look for the first = character. */
		p = strchr(buf, '=');

		/* Missing separator? */
		if (p == NULL)
			goto err2;

		/* Replace separator with NUL and point p at the value. */
		*p++ = '\0';

		/* We should have ACCESS_KEY_ID or ACCESS_KEY_SECRET. */
		if (strcmp(buf, "ACCESS_KEY_ID") == 0) {
			/* Copy key ID string. */
			if (*key_id != NULL) {
				warn0("ACCESS_KEY_ID specified twice");
				goto err1;
			}
			if ((*key_id = strdup(p)) == NULL)
				goto err1;
		} else if (strcmp(buf, "ACCESS_KEY_SECRET") == 0) {
			/* Copy key secret string. */
			if (*key_secret != NULL) {
				warn0("ACCESS_KEY_SECRET specified twice");
				goto err1;
			}
			if ((*key_secret = strdup(p)) == NULL)
				goto err1;
		} else
			goto err2;
	}

	/* Check for error. */
	if (ferror(f)) {
		warnp("Error reading %s", fname);
		goto err1;
	}

	/* Close the file. */
	if (fclose(f)) {
		warnp("fclose");
		goto err0;
	}

	/* Check that we got the necessary keys. */
	if ((*key_id == NULL) || (*key_secret == NULL)) {
		warn0("Need ACCESS_KEY_ID and ACCESS_KEY_SECRET");
		goto err0;
	}

	/* Success! */
	return (0);

err2:
	warn0("Lines in %s must be ACCESS_KEY_(ID|SECRET)=...", fname);
err1:
	fclose(f);
err0:
	/* Failure! */
	return (-1);
}

static int
s3_put(const char * key_id, const char * key_secret, const char * region,
    const char * bucket, const char * path, const uint8_t * buf, size_t buflen)
{
	char * x_amz_content_sha256;
	char * x_amz_date;
	char * authorization;
	char * host;
	char * headers;
	uint8_t * req;
	const char * errstr;
	uint8_t * resp;
	size_t len;
	size_t resplen;
	size_t pos;

	/* Sign request. */
	if (aws_sign_s3_headers(key_id, key_secret, region, "PUT", bucket,
	    path, buf, buflen, &x_amz_content_sha256, &x_amz_date,
	    &authorization)) {
		warnp("Failed to sign PUT request");
		goto err0;
	}

	/* Construct request header and compute length. */
	if (asprintf(&headers,
	    "PUT %s HTTP/1.1\r\n"
	    "Host: %s.s3.amazonaws.com\r\n"
	    "X-Amz-Date: %s\r\n"
	    "X-Amz-Content-SHA256: %s\r\n"
	    "Authorization: %s\r\n"
	    "Content-Length: %zu\r\n"
	    "Connection: close\r\n"
	    "\r\n",
	    path, bucket, x_amz_date, x_amz_content_sha256,
	    authorization, buflen) == -1)
		goto err1;
	len = strlen(headers);

	/* Append request body. */
	if ((req = realloc(headers, len + buflen)) == NULL) {
		free(headers);
		goto err1;
	}
	memcpy(&req[len], buf, buflen);
	len += buflen;

	/* Construct S3 endpoint name. */
	if (strcmp(region, "us-east-1")) {
		if (asprintf(&host, "s3-%s.amazonaws.com", region) == -1)
			goto err2;
	} else {
		if (asprintf(&host, "s3.amazonaws.com", region) == -1)
			goto err2;
	}

	/* Allocate space for a 16 kB response plus a trailing NUL. */
	resplen = 16384;
	if ((resp = malloc(resplen + 1)) == NULL)
		goto err3;

	/* Send the request. */
	if ((errstr = sslreq(host, "443", CERTFILE, req, len, resp, &resplen))
	    != NULL) {
		warnp("SSL request failed: %s", errstr);
		goto err4;
	}

	/* NUL-terminate the response. */
	resp[resplen] = '\0';

        /* Find the end of the first line. */
        pos = strcspn(resp, "\r\n");

        /* Look for a "200" status on the first line. */
        if ((strstr(resp, " 200 ") == NULL) ||
            (strstr(resp, " 200 ") > (char *)&resp[pos])) {
		warnp("S3 request failed:\n%s\n", resp);
		goto err4;
	}

	/* Free response. */
	free(resp);

	/* Free request buffers. */
	free(host);
	free(req);
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);

	/* Success! */
	return (0);

err4:
	free(resp);
err3:
	free(host);
err2:
	free(req);
err1:
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
err0:
	/* Failure! */
	return (-1);
}

static int
s3_put_loop(const char * key_id, const char * key_secret, const char * region,
    const char * bucket, const char * path, const uint8_t * buf, size_t buflen)
{
	int i;

	/* Try up to 10 times. */
	for (i = 0; i < 10; i++) {
		if (s3_put(key_id, key_secret, region, bucket, path,
		    buf, buflen) == 0)
			return (0);
		fprintf(stderr, "S3 PUT failed %d times: %s\n", i + 1, path);
	}

	/* Give up. */
	return (-1);
}

static char *
uploadvolume(const char * fname, const char * region, const char * bucket,
    uint64_t * size, const char * key_id, const char * key_secret)
{
	FILE * f;
	struct stat sb;
	uint8_t nonce[16];
	char noncehex[33];
	uint8_t * buf;
	size_t buflen = PARTSZ;
	off_t pos;
	char * path;
	STR manifest;
	char * s;
	char * query;
	size_t len;

	/* Get a random value to use as a nonce in our paths. */
	if (entropy_read(nonce, 16)) {
		warnp("Cannot generate nonce");
		goto err0;
	}
	hexify(nonce, noncehex, 16);

	/* Open the disk image and determine its length. */
	if ((f = fopen(fname, "r")) == NULL) {
		warnp("Cannot open disk image: %s", fname);
		goto err0;
	}
	if (fstat(fileno(f), &sb)) {
		warnp("Cannot stat: %s", fname);
		goto err1;
	}

	/* Allocate a buffer for holding a part. */
	if ((buf = malloc(buflen)) == NULL)
		goto err1;

	/* Create an elastic string for the manifest. */
	if ((manifest = str_init(0)) == NULL)
		goto err2;

	/* Generate manifest "self-destruct" query string. */
	if (asprintf(&path, "/%s/manifest.xml", noncehex) == -1)
		goto err3;
	if ((query = aws_sign_s3_querystr(key_id, key_secret, region, "DELETE",
	    bucket, path, 604800)) == NULL) {
		warnp("Error generating presigned URL");
		goto err4;
	}
	if ((query = encodeamp(query)) == NULL)
		goto err4;

	/* Construct the start of the manifest file. */
	if (asprintf(&s,
	    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
	    "<manifest>"
		"<version>2010-11-15</version>"
		"<file-format>RAW</file-format>"
		"<importer>"
		    "<name>bsdec2-image-upload</name>"
		    "<version>1.1.3</version>"
		    "<release>2017-07-11</release>"
		"</importer>"
		"<self-destruct-url>https://%s.s3.amazonaws.com%s?%s</self-destruct-url>"
		"<import>"
		    "<size>%" PRId64 "</size>"
		    "<volume-size>%d</volume-size>"
		    "<parts count=\"%" PRId64 "\">",
	    bucket, path, query, (uint64_t)sb.st_size,
	    (int)((sb.st_size + (1 << 30) - 1) / (1 << 30)),
	    (uint64_t)(sb.st_size + PARTSZ - 1) / PARTSZ) == -1)
		goto err5;
	if (str_append(manifest, s, strlen(s)))
		goto err6;
	free(s);
	free(query);
	free(path);

	/* Say what we're doing. */
	fprintf(stderr, "Uploading %s to\nhttp://%s.s3.amazonaws.com/%s/\n"
	    "in %" PRId64 " part(s)", fname, bucket, noncehex,
	    (uint64_t)(sb.st_size + PARTSZ - 1) / PARTSZ);

	/* Upload parts one by one. */
	for (pos = 0; pos < sb.st_size; pos += buflen) {
		/* Print one dot per part. */
		fprintf(stderr, ".");

		/* Shorter part if we're going to hit EOF. */
		if (sb.st_size - pos < (off_t)buflen)
			buflen = sb.st_size - pos;

		/* Read part. */
		if (fread(buf, buflen, 1, f) != 1) {
			warnp("Error reading file: %s", fname);
			goto err3;
		}

		/* Generate part path. */
		if (asprintf(&path, "/%s/part%" PRIu64, noncehex,
		    (uint64_t)(pos / PARTSZ)) == -1)
			goto err3;

		/* Upload to S3. */
		if (s3_put_loop(key_id, key_secret, region, bucket, path,
		    buf, buflen)) {
			warnp("PUT failed");
			goto err4;
		}

		/* Construct the start of the <part> block. */
		if (asprintf(&s,
		    "<part index=\"%" PRId64 "\">"
			"<byte-range start=\"%" PRId64 "\" end=\"%" PRId64 "\"/>"
			"<key>%s/part%" PRIu64 "</key>",
		    (uint64_t)(pos / PARTSZ), pos, pos + buflen - 1, noncehex,
		    (uint64_t)(pos / PARTSZ)) == -1)
			goto err4;
		if (str_append(manifest, s, strlen(s))) {
			free(s);
			goto err4;
		}

		/* Generate <head-url> block. */
		if ((query = aws_sign_s3_querystr(key_id, key_secret, region,
		    "HEAD", bucket, path, 604800)) == NULL) {
			warnp("Error generating presigned URL");
			goto err4;
		}
		if ((query = encodeamp(query)) == NULL)
			goto err4;
		if (asprintf(&s,
		    "<head-url>https://%s.s3.amazonaws.com%s?%s</head-url>",
		    bucket, path, query) == -1)
			goto err5;
		if (str_append(manifest, s, strlen(s)))
			goto err6;
		free(s);
		free(query);

		/* Generate <get-url> block. */
		if ((query = aws_sign_s3_querystr(key_id, key_secret, region,
		    "GET", bucket, path, 604800)) == NULL) {
			warnp("Error generating presigned URL");
			goto err4;
		}
		if ((query = encodeamp(query)) == NULL)
			goto err4;
		if (asprintf(&s,
		    "<get-url>https://%s.s3.amazonaws.com%s?%s</get-url>",
		    bucket, path, query) == -1)
			goto err5;
		if (str_append(manifest, s, strlen(s)))
			goto err6;
		free(s);
		free(query);

		/* Generate <delete-url> block. */
		if ((query = aws_sign_s3_querystr(key_id, key_secret, region,
		    "DELETE", bucket, path, 604800)) == NULL) {
			warnp("Error generating presigned URL");
			goto err4;
		}
		if ((query = encodeamp(query)) == NULL)
			goto err4;
		if (asprintf(&s,
		    "<delete-url>https://%s.s3.amazonaws.com%s?%s</delete-url>",
		    bucket, path, query) == -1)
			goto err5;
		if (str_append(manifest, s, strlen(s)))
			goto err6;
		free(s);
		free(query);

		/* Append closing tag. */
		s = "</part>";
		if (str_append(manifest, s, strlen(s)))
			goto err4;

		/* Free string allocated by asprintf. */
		free(path);
	}

	/* Report completion. */
	fprintf(stderr, " done.\n");

	/* Append the end of the manifest file. */
	s = "</parts></import></manifest>";
	if (str_append(manifest, s, strlen(s)))
		goto err3;

	/* Export manifest string. */
	if (str_export(manifest, &s, &len))
		goto err2;

	/* Say what we're doing. */
	fprintf(stderr, "Uploading volume manifest...");

	/* Upload manifest. */
	if (asprintf(&path, "/%s/manifest.xml", noncehex) == -1) {
		free(s);
		goto err2;
	}
	if (s3_put_loop(key_id, key_secret, region, bucket, path, s, len)) {
		free(path);
		free(s);
		goto err2;
	}
	free(s);

	/* Report completion. */
	fprintf(stderr, " done.\n");

	/* Return disk image size. */
	*size = sb.st_size;

	/* Return manifest file path. */
	return (path);

err6:
	free(s);
err5:
	free(query);
err4:
	free(path);
err3:
	str_free(manifest);
err2:
	free(buf);
err1:
	fclose(f);
err0:
	/* Failure! */
	return (NULL);
}

static char *
ec2_apicall(const char * key_id, const char * key_secret, const char * region,
    const char * s)
{
	char * x_amz_content_sha256;
	char * x_amz_date;
	char * authorization;
	char * req;
	char * host;
	size_t len;
	const char * errstr;
	uint8_t * resp;
	size_t resplen;
	size_t pos;
	uint8_t * body;

	/* Sign request. */
	if (aws_sign_ec2_headers(key_id, key_secret, region, s, strlen(s),
	    &x_amz_content_sha256, &x_amz_date, &authorization)) {
		warnp("Failed to sign EC2 POST request");
		goto err0;
	}

	/* Construct request and compute length. */
	if (asprintf(&req,
	    "POST / HTTP/1.0\r\n"
	    "Host: ec2.%s.amazonaws.com\r\n"
	    "X-Amz-Date: %s\r\n"
	    "X-Amz-Content-SHA256: %s\r\n"
	    "Authorization: %s\r\n"
	    "Content-Length: %zu\r\n"
	    "Connection: close\r\n"
	    "\r\n"
	    "%s",
	    region, x_amz_date, x_amz_content_sha256, authorization,
	    strlen(s), s) == -1)
		goto err1;
	len = strlen(req);

	/* Construct EC2 endpoint name. */
	if (asprintf(&host, "ec2.%s.amazonaws.com", region) == -1)
		goto err2;

	/* Allocate space for a 16 kB response plus a trailing NUL. */
	resplen = 16384;
	if ((resp = malloc(resplen + 1)) == NULL)
		goto err3;

	/* Send the request. */
	if ((errstr = sslreq(host, "443", CERTFILE, req, len, resp, &resplen))
	    != NULL) {
		warnp("SSL request failed: %s", errstr);
		goto err4;
	}

	/* NUL-terminate the response. */
	resp[resplen] = '\0';

	/* EC2 API responses should not contain NUL bytes. */
	if (strlen(resp) != resplen) {
		warnp("NUL byte in EC2 API response");
		goto err4;
	}

        /* Find the end of the first line. */
        pos = strcspn(resp, "\r\n");

        /* Look for a "200" status on the first line. */
        if ((strstr(resp, " 200 ") == NULL) ||
            (strstr(resp, " 200 ") > (char *)&resp[pos])) {
		warnp("EC2 API request failed:\n%s\n", resp);
		goto err4;
	}

	/* Find the end of the headers. */
	if ((body = strstr(resp, "\r\n\r\n")) == NULL) {
		warnp("Bad EC2 API response received:\n%s\n", resp);
		goto err4;
	}

	/* Skip to the start of the response body. */
	body = &body[4];

	/* Duplicate response body. */
	if ((body = strdup(body)) == NULL)
		goto err4;

	/* Free repsonse buffer. */
	free(resp);

	/* Free request buffers. */
	free(host);
	free(req);
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);

	/* Success! */
	return (body);

err4:
	free(resp);
err3:
	free(host);
err2:
	free(req);
err1:
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
err0:
	/* Failure! */
	return (NULL);
}

static char *
ec2_apicall_loop(const char * key_id, const char * key_secret,
    const char * region, const char * s)
{
	char * body;
	int i;

	/* Try up to 10 times. */
	for (i = 0; i < 10; i++) {
		body = ec2_apicall(key_id, key_secret, region, s);
		if (body != NULL)
			return (body);
		fprintf(stderr, "EC2 API call failed %d times\n", i + 1);
	}

	/* Give up. */
	return (NULL);
}

static int
xmlextracts(const char * _s, const char * tagname,
    char *** vals, size_t * nvals)
{
	char * s;
	char * sorig;
	char * tag;
	char * stag;
	STRARRAY vallist;
	char * pst;
	char * pend;
	char * contents;
	size_t i;

	/* Duplicate the string so we can safely mangle it. */
	if ((sorig = s = strdup(_s)) == NULL)
		goto err0;

	/* Construct "<tagname>" and "</tagname>". */
	if (asprintf(&tag, "<%s>", tagname) == -1)
		goto err1;
	if (asprintf(&stag, "</%s>", tagname) == -1)
		goto err2;

	/* Allocate array of tag contents. */
	if ((vallist = strarray_init(0)) == NULL)
		goto err3;

	/* Find tags. */
	while ((pst = strstr(s, tag)) != NULL) {
		pst += strlen(tag);

		/* Look for </tagname>. */
		if ((pend = strstr(pst, stag)) == NULL) {
			errno = 0;
			goto err4;
		}

		/* Advance the remaining string pointer. */
		s = pend + strlen(stag);

		/* Duplicate tag contents. */
		pend[0] = '\0';
		if ((contents = strdup(pst)) == NULL)
			goto err4;

		/* Add to elastic array. */
		if (strarray_append(vallist, &contents, 1))
			goto err5;
	}

	/* Export the array of tag contents strings. */
	if (strarray_export(vallist, vals, nvals))
		goto err4;

	/* Free strings constructed and duplicated. */
	free(stag);
	free(tag);
	free(sorig);

	/* Success! */
	return (0);

err5:
	free(contents);
err4:
	for (i = 0; i < strarray_getsize(vallist); i++)
		free(*strarray_get(vallist, i));
	strarray_free(vallist);
err3:
	free(stag);
err2:
	free(tag);
err1:
	free(sorig);
err0:
	/* Failure! */
	return (-1);
}

static char *
xmlextract(const char * _s, const char * tagname)
{
	char ** vals;
	size_t nvals;
	char * contents;

	/* Extract all of the tags, if any. */
	if (xmlextracts(_s, tagname, &vals, &nvals))
		goto err0;

	/* There should be at least one such tag. */
	if (nvals == 0) {
		errno = 0;
		goto err1;
	}

	/* Pull out the first tag contents. */
	contents = vals[0];

	/* Free everything else we were passed. */
	while (nvals > 1)
		free(vals[--nvals]);
	free(vals);

	/* Return contents of tag. */
	return (contents);

err1:
	while (nvals > 0)
		free(vals[--nvals]);
	free(vals);
err0:
	/* Failure! */
	return (NULL);
}

static int
getregionlist(const char * key_id, const char * key_secret,
    const char * region, char *** regions, size_t * nregions)
{
	char * resp;
	char * regionInfo;

	/* Ask EC2 for a list of regions. */
	if ((resp = ec2_apicall_loop(key_id, key_secret, region,
	    "Action=DescribeRegions&"
	    "Version=2014-09-01")) == NULL)
		goto err0;

	/* Extract the <regionInfo>. */
	if ((regionInfo = xmlextract(resp, "regionInfo")) == NULL) {
		warnp("Could not find regionInfo in DescribeRegions response:\n%s\n",
		    resp);
		goto err1;
	}

	/* Extract the <regionName> tags. */
	if (xmlextracts(regionInfo, "regionName", regions, nregions))
		goto err2;

	/* Sanity-check: There should be at least 1 region. */
	if (*nregions == 0) {
		warn0("Could not find any regions in DescribeRegions response:\n%s\n",
		    resp);
		goto err3;
	}

	/* Free the response and extracted regionInfo strings. */
	free(regionInfo);
	free(resp);

	/* Success! */
	return (0);

err3:
	while (*nregions > 0)
		free((*regions)[--(*nregions)]);
	free(*regions);
err2:
	free(regionInfo);
err1:
	free(resp);
err0:
	/* Failure! */
	return (-1);
}

static char *
importvolume(const char * region, const char * bucket, const char * manifest,
    uint64_t size, const char * key_id, const char * key_secret)
{
	char * query;
	char * url;
	char * urlenc;
	char * s;
	char * resp;
	char * taskid;

	/* Generate query string for presigned URL to manifest file. */
	if ((query = aws_sign_s3_querystr(key_id, key_secret, region, "GET",
	    bucket, manifest, 604800)) == NULL)
		goto err0;
	if (asprintf(&url, "https://%s.s3.amazonaws.com%s?%s",
	    bucket, manifest, query) == -1)
		goto err1;
	if ((urlenc = rfc3986_encode(url)) == NULL)
		goto err2;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=ImportVolume&"
	    "AvailabilityZone=%sa&"
	    "Image.Format=RAW&"
	    "Image.Bytes=%" PRId64 "&"
	    "Image.ImportManifestUrl=%s&"
	    "Volume.Size=%" PRId64 "&"
	    "Version=2014-09-01",
	    region, size, urlenc, (size + (1 << 30) - 1) / (1 << 30)) == -1)
		goto err3;

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, region, s)) == NULL)
		goto err4;

	/* Extract the conversion task ID. */
	if ((taskid = xmlextract(resp, "conversionTaskId")) == NULL) {
		warnp("Could not find conversionTaskID in ImportVolume response:\n%s\n",
		    resp);
		goto err5;
	}

	/* Free response, request, and parts thereof. */
	free(resp);
	free(s);
	free(urlenc);
	free(url);
	free(query);

	/* Return conversion task ID. */
	return (taskid);

err5:
	free(resp);
err4:
	free(s);
err3:
	free(urlenc);
err2:
	free(url);
err1:
	free(query);
err0:
	/* Failure! */
	return (NULL);
}

static void
printstatus(const char * prefix, char * status, char ** laststatus)
{

	/* Comparing old status to new status... */
	if (*laststatus == NULL) {
		/* No old status?  We have a status now. */
		*laststatus = status;
		fprintf(stderr, "%s: %s", prefix, status);
	} else if (strcmp(status, *laststatus)) {
		/* Status has changed. */
		fprintf(stderr, "\n");
		free(*laststatus);
		*laststatus = status;
		fprintf(stderr, "%s: %s", prefix, status);
	} else {
		/* Status is unchanged. */
		fprintf(stderr, ".");
		free(status);
	}
}

static char *
waitforimport(const char * region, const char * taskid,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;
	char * volume;
	char * volid;
	char * status;
	char * laststatus = NULL;

	/* Loop until we're finished. */
	do {
		/* Generate EC2 API request. */
		if (asprintf(&s,
		    "Action=DescribeConversionTasks&"
		    "ConversionTaskId.1=%s&"
		    "Version=2014-09-01",
		    taskid) == -1)
			goto err0;

		/* Issue API request. */
		if ((resp = ec2_apicall_loop(key_id, key_secret, region, s))
		    == NULL)
			goto err1;

		/* Find <volume> tag. */
		if ((volume = xmlextract(resp, "volume")) == NULL) {
			warnp("Could not find <volume> in DescribeConversionTasks response: %s", resp);
			goto err2;
		}

		/* Is there an <id> tag? */
		if ((volid = xmlextract(volume, "id")) != NULL) {
			/* We're done! */
			break;
		}

		/* Look for a <statusMessage> tag. */
		if ((status = xmlextract(resp, "statusMessage")) == NULL) {
			warnp("Could not find <statusMessage> in DescribeConversionTasks response: %s", resp);
			goto err3;
		}

		/* Print status as appropriate. */
		printstatus("Importing volume", status, &laststatus);

		/* Free contents of <volume> tag and API response. */
		free(volume);
		free(resp);

		/* Free request. */
		free(s);

		/* Wait 10 seconds before making another API call. */
		sleep(10);
	} while(1);

	/* We're done! */
	fprintf(stderr, " done.\n");

	/* Free extracted tag and API response. */
	free(volume);
	free(resp);

	/* Free request. */
	free(s);

	/* Free previous returned status. */
	free(laststatus);

	/* Return volume ID. */
	return (volid);

err3:
	free(volume);
err2:
	free(resp);
err1:
	free(s);
	free(laststatus);
err0:
	/* Failure! */
	return (NULL);
}

static char *
createsnapshot(const char * region, const char * volume,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;
	char * snapshot;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=CreateSnapshot&"
	    "VolumeId=%s&"
	    "Version=2014-09-01",
	    volume) == -1)
		goto err0;

	/* Say what we're doing. */
	fprintf(stderr, "Creating snapshot");

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, region, s)) == NULL)
		goto err1;

	/* Find <snapshotId> tag. */
	if ((snapshot = xmlextract(resp, "snapshotId")) == NULL) {
		warnp("Could not find <snapshotId> in CreateSnapshot response: %s", resp);
		goto err2;
	}

	/* Free API response. */
	free(resp);

	/* Free request. */
	free(s);

	/* Return snapshot ID. */
	return (snapshot);

err2:
	free(resp);
err1:
	free(s);
err0:
	/* Failure! */
	return (NULL);
}

static int
waitforsnapshot(const char * region, const char * snapshot,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;
	char * status;

	/* Loop until we're finished. */
	do {
		/* Generate EC2 API request. */
		if (asprintf(&s,
		    "Action=DescribeSnapshots&"
		    "SnapshotId.1=%s&"
		    "Version=2014-09-01",
		    snapshot) == -1)
			goto err0;

		/* Issue API request. */
		if ((resp = ec2_apicall_loop(key_id, key_secret, region, s))
		    == NULL)
			goto err1;

		/* Find <status> tag. */
		if ((status = xmlextract(resp, "status")) == NULL) {
			warnp("Could not find <status> in DescribeSnapshots response: %s", resp);
			goto err2;
		}

		/* Status should be "pending", "completed", or "error". */
		if (strcmp(status, "completed") == 0) {
			/* We're done! */
			break;
		} else if (strcmp(status, "pending") == 0) {
			/* We need to try again. */
			fprintf(stderr, ".");
		} else {
			/* Something bad happened. */
			warnp("Bad status from DescribeSnapshots: %s", status);
			goto err3;
		}

		/* Free contents of <status> tag and API response. */
		free(status);
		free(resp);

		/* Free request. */
		free(s);

		/* Wait 10 seconds before making another API call. */
		sleep(10);
	} while(1);

	/* We're done! */
	fprintf(stderr, " done.\n");

	/* Free contents of <status> tag and API response. */
	free(status);
	free(resp);

	/* Free request. */
	free(s);

	/* Success! */
	return (0);

err3:
	free(status);
err2:
	free(resp);
err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static int
deletevolume(const char * region, const char * volume,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=DeleteVolume&"
	    "VolumeId=%s&"
	    "Version=2014-09-01",
	    volume) == -1)
		goto err0;

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, region, s)) == NULL)
		goto err1;

	/* Make sure that we succeeded. */
	if (strstr(resp, "<return>true</return>") == NULL) {
		warnp("DeleteVolume failed: %s", resp);
		goto err2;
	}

	/* Free API response. */
	free(resp);

	/* Free request. */
	free(s);

	/* Return AMI. */
	return (0);

err2:
	free(resp);
err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static char *
registerimage(const char * region, const char * snapshot, const char * name,
    const char * desc, int sriov, int ena,
    const char * key_id, const char * key_secret)
{
	char * nameenc;
	char * descenc;
	char * s;
	char * resp;
	char * ami;

	/* Encode name and description strings. */
	if ((nameenc = rfc3986_encode(name)) == NULL)
		goto err0;
	if ((descenc = rfc3986_encode(desc)) == NULL)
		goto err1;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=RegisterImage&"
	    "Name=%s&"
	    "Description=%s&"
	    "Architecture=x86_64&"
	    "RootDeviceName=%%2Fdev%%2Fsda1&"
	    "VirtualizationType=hvm&"
	    "%s"
	    "%s"
	    "BlockDeviceMapping.1.DeviceName=%%2Fdev%%2Fsda1&"
	    "BlockDeviceMapping.1.Ebs.SnapshotId=%s&"
	    "BlockDeviceMapping.1.Ebs.VolumeType=gp2&"
	    "BlockDeviceMapping.1.Ebs.VolumeSize=10&"
	    "BlockDeviceMapping.2.DeviceName=%%2Fdev%%2Fsdb&"
	    "BlockDeviceMapping.2.VirtualName=ephemeral0&"
	    "BlockDeviceMapping.3.DeviceName=%%2Fdev%%2Fsdc&"
	    "BlockDeviceMapping.3.VirtualName=ephemeral1&"
	    "BlockDeviceMapping.4.DeviceName=%%2Fdev%%2Fsdd&"
	    "BlockDeviceMapping.4.VirtualName=ephemeral2&"
	    "BlockDeviceMapping.5.DeviceName=%%2Fdev%%2Fsde&"
	    "BlockDeviceMapping.5.VirtualName=ephemeral3&"
	    "Version=2016-11-15",
	    nameenc, descenc, sriov ? "SriovNetSupport=simple&" : "",
	    ena ? "EnaSupport=true&" : "",
	    snapshot) == -1)
		goto err2;

	/*
	 * Say what we're doing.  Include ... here because AMIs will usually
	 * be ready as soon as this API call returns, so there won't be any
	 * spinning in DescribeImages to produce dots.
	 */
	fprintf(stderr, "Registering AMI...");

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, region, s)) == NULL)
		goto err3;

	/* Find <imageId> tag. */
	if ((ami = xmlextract(resp, "imageId")) == NULL) {
		warnp("Could not find <imageId> in RegisterImage response: %s", resp);
		goto err4;
	}

	/* Free API response. */
	free(resp);

	/* Free request and parts thereof. */
	free(s);
	free(descenc);
	free(nameenc);

	/* Return AMI. */
	return (ami);

err4:
	free(resp);
err3:
	free(s);
err2:
	free(descenc);
err1:
	free(nameenc);
err0:
	/* Failure! */
	return (NULL);
}

static int
waitforami(const char * region, const char * ami,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;
	char * status;

	/* Loop until we're finished. */
	do {
		/* Generate EC2 API request. */
		if (asprintf(&s,
		    "Action=DescribeImages&"
		    "ImageId.1=%s&"
		    "Version=2014-09-01",
		    ami) == -1)
			goto err0;

		/* Issue API request. */
		if ((resp = ec2_apicall_loop(key_id, key_secret, region, s))
		    == NULL)
			goto err1;

		/* Find <imageState> tag. */
		if ((status = xmlextract(resp, "imageState")) == NULL) {
			warnp("Could not find <imageState> in DescribeImages response: %s", resp);
			goto err2;
		}

		/* Status should be "pending", "available", or "error". */
		if (strcmp(status, "available") == 0) {
			/* We're done! */
			break;
		} else if (strcmp(status, "pending") == 0) {
			/* We need to try again. */
			fprintf(stderr, ".");
		} else {
			/* Something bad happened. */
			warnp("Bad status from DescribeImages: %s", status);
			goto err3;
		}

		/* Free contents of <imageState> tag and API response. */
		free(status);
		free(resp);

		/* Free request. */
		free(s);

		/* Wait 10 seconds before making another API call. */
		sleep(10);
	} while(1);

	/* We're done! */
	fprintf(stderr, " done.\n");

	/* Free contents of <imageState> tag and API response. */
	free(status);
	free(resp);

	/* Free request. */
	free(s);

	/* Success! */
	return (0);

err3:
	free(status);
err2:
	free(resp);
err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static char *
copyimage(const char * region, const char * ami, const char * toregion,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;
	char * toami;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=CopyImage&"
	    "SourceRegion=%s&"
	    "SourceImageId=%s&"
	    "Version=2014-09-01",
	    region, ami) == -1)
		goto err0;

	/*
	 * Say what we're doing.  Include ... here because AMIs will usually
	 * be ready as soon as this API call returns, so there won't be any
	 * spinning in DescribeImages to produce dots.
	 */
	fprintf(stderr, "Copying AMI to %s", toregion);

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, toregion, s)) == NULL)
		goto err1;

	/* Find <imageId> tag. */
	if ((toami = xmlextract(resp, "imageId")) == NULL) {
		warnp("Could not find <imageId> in CopyImage response: %s", resp);
		goto err2;
	}

	/* Free API response. */
	free(resp);

	/* Free request. */
	free(s);

	/* Wait for AMI to finish copying. */
	if (waitforami(toregion, toami, key_id, key_secret)) {
		warnp("Failure waiting for AMI");
		free(toami);
		goto err0;
	}

	/* Return AMI. */
	return (toami);

err2:
	free(resp);
err1:
	free(s);
err0:
	/* Failure! */
	return (NULL);
}

static int
makepublic(const char * region, const char * ami,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=ModifyImageAttribute&"
	    "ImageId=%s&"
	    "LaunchPermission.Add.1.Group=all&"
	    "Version=2014-09-01",
	    ami) == -1)
		goto err0;

	/* Issue API request. */
	if ((resp = ec2_apicall_loop(key_id, key_secret, region, s)) == NULL)
		goto err1;

	/* Make sure that we succeeded. */
	if (strstr(resp, "<return>true</return>") == NULL) {
		warnp("ModifyImageAttribute failed: %s", resp);
		goto err2;
	}

	/* Free API response. */
	free(resp);

	/* Free request. */
	free(s);

	/* Return AMI. */
	return (0);

err2:
	free(resp);
err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

int
main(int argc, char * argv[])
{
	int public = 0;
	int sriov = 0;
	int ena = 0;
	const char * diskimg;
	const char * name;
	const char * desc;
	const char * region;
	const char * bucket;
	const char * keyfile;
	char * key_id;
	char * key_secret;
	char ** regions;
	size_t nregions;
	char * manifest;
	uint64_t size;
	char * taskid;
	char * volume;
	char * snapshot;
	char * ami;
	char ** amis;
	size_t i;

	WARNP_INIT;

	/* Look for --public and/or --sriov flags. */
	while (argc > 1) {
		if (strcmp(argv[1], "--public") == 0)
			public = 1;
		else if (strcmp(argv[1], "--sriov") == 0)
			sriov = 1;
		else if (strcmp(argv[1], "--ena") == 0)
			ena = 1;
		else
			break;
		argc--;
		argv++;
	}

	/* Sanity-check. */
	if (argc != 7) {
		fprintf(stderr, "usage: bsdec2-image-upload [--public]"
		    " [--sriov] [--ena]"
		    " %s %s %s %s %s %s\n",
		    "<disk image>", "<name>", "<description>",
		    "<region>", "<bucket>", "<AWS keyfile>");
		exit(1);
	}
	diskimg = argv[1];
	name = argv[2];
	desc = argv[3];
	region = argv[4];
	bucket = argv[5];
	keyfile = argv[6];

	/* Load AWS keys. */
	if (readkeys(keyfile, &key_id, &key_secret)) {
		warnp("Cannot read AWS keys");
		exit(1);
	}

	/* Get list of AWS regions. */
	if (getregionlist(key_id, key_secret, region, &regions, &nregions)) {
		warnp("Failure getting list of AWS regions");
		exit(1);
	}

	/* Upload disk image. */
	if ((manifest = uploadvolume(diskimg, region, bucket,
	    &size, key_id, key_secret)) == NULL) {
		warnp("Failure uploading disk image");
		exit(1);
	}

	/* Issue ImportVolume call. */
	if ((taskid = importvolume(region, bucket, manifest, size,
	    key_id, key_secret)) == NULL) {
		warnp("Failure importing disk image");
		exit(1);
	}

	/* Wait for the volume to be ready. */
	if ((volume = waitforimport(region, taskid,
	    key_id, key_secret)) == NULL) {
		warnp("Failure waiting for EBS volume");
		exit(1);
	}

	/* Create a snapshot. */
	if ((snapshot = createsnapshot(region, volume,
	    key_id, key_secret)) == NULL) {
		warnp("Failure creating snapshot");
		exit(1);
	}

	/* Wait for the snapshot to be ready. */
	if (waitforsnapshot(region, snapshot, key_id, key_secret)) {
		warnp("Failure waiting for EBS snapshot");
		exit(1);
	}

	/* Delete the volume now that it is snapshotted. */
	if (deletevolume(region, volume, key_id, key_secret)) {
		warnp("Failure deleting EBS volume");
		exit(1);
	}

	/* Register an image. */
	if ((ami = registerimage(region, snapshot, name, desc, sriov, ena,
	    key_id, key_secret)) == NULL) {
		warnp("Failure registering AMI");
		exit(1);
	}

	/* Wait for the AMI to be ready. */
	if (waitforami(region, ami, key_id, key_secret)) {
		warnp("Failure waiting for AMI");
		exit(1);
	}

	/* If we're not making public images, stop here. */
	if (!public) {
		printf("Created AMI in %s region: %s\n", region, ami);
		exit(0);
	}

	/* Allocate array of AMI names. */
	if ((amis = malloc(nregions * sizeof(char *))) == NULL) {
		warnp("malloc");
		exit(1);
	}

	/* Copy images into the regions. */
	for (i = 0; i < nregions; i++) {
		/* Don't copy to the region where we built the image. */
		if (strcmp(regions[i], region) == 0) {
			if ((amis[i] = strdup(ami)) == NULL) {
				warnp("strdup");
				exit(1);
			}
			continue;
		}

		if ((amis[i] = copyimage(region, ami, regions[i],
		    key_id, key_secret)) == NULL) {
			warnp("Error copying AMI to region %s", regions[i]);
			exit(1);
		}
	}

	/* Mark images as public. */
	fprintf(stderr, "Marking images as public...");
	for (i = 0; i < nregions; i++) {
		if (makepublic(regions[i], amis[i], key_id, key_secret)) {
			warnp("Error marking AMI as public");
			exit(1);
		}
	}
	fprintf(stderr, " done.\n");

	/* Print the list of AMIs. */
	for (i = 0; i < nregions; i++)
		printf("Created AMI in %s region: %s\n", regions[i], amis[i]);

	return (0);
}
