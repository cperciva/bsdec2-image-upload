#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asprintf.h"
#include "aws_readkeys.h"
#include "aws_sign.h"
#include "elasticarray.h"
#include "entropy.h"
#include "getopt.h"
#include "hexify.h"
#include "rfc3986.h"
#include "sslreq.h"
#include "warnp.h"

#ifndef CERTFILE
#define CERTFILE NULL
#endif
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
s3_put(const char * key_id, const char * key_secret, const char * region,
    const char * bucket, const char * path, const uint8_t * buf, size_t buflen)
{
	char * x_amz_content_sha256;
	char * x_amz_date;
	char * authorization;
	char * host;
	char * headers;
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
	    "Host: %s.s3.%s.amazonaws.com\r\n"
	    "X-Amz-Date: %s\r\n"
	    "X-Amz-Content-SHA256: %s\r\n"
	    "Authorization: %s\r\n"
	    "Content-Length: %zu\r\n"
	    "Connection: close\r\n"
	    "\r\n",
	    path, bucket, region, x_amz_date, x_amz_content_sha256,
	    authorization, buflen) == -1)
		goto err1;
	len = strlen(headers);

	/* Construct S3 endpoint name. */
	if (asprintf(&host, "%s.s3.%s.amazonaws.com", bucket, region) == -1)
		goto err2;

	/* Allocate space for a 16 kB response plus a trailing NUL. */
	resplen = 16384;
	if ((resp = malloc(resplen + 1)) == NULL)
		goto err3;

	/* Send the request. */
	if ((errstr = sslreq2(host, "443", CERTFILE, (uint8_t *)headers, len,
	    buf, buflen, resp, &resplen)) != NULL) {
		warnp("SSL request failed: %s", errstr);
		goto err4;
	}

	/* NUL-terminate the response. */
	resp[resplen] = '\0';

        /* Find the end of the first line. */
        pos = strcspn((char *)resp, "\r\n");

        /* Look for a "200" status on the first line. */
        if ((strstr((char *)resp, " 200 ") == NULL) ||
            (strstr((char *)resp, " 200 ") > (char *)&resp[pos])) {
		warnp("S3 request failed:\n%s\n", resp);
		goto err4;
	}

	/* Free response. */
	free(resp);

	/* Free request buffers. */
	free(host);
	free(headers);
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
	free(headers);
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
		    "<version>@VERSION@</version>"
		    "<release>@ISODATE@</release>"
		"</importer>"
		"<self-destruct-url>https://%s.s3.%s.amazonaws.com%s?%s</self-destruct-url>"
		"<import>"
		    "<size>%" PRId64 "</size>"
		    "<volume-size>%d</volume-size>"
		    "<parts count=\"%" PRId64 "\">",
	    bucket, region, path, query, (uint64_t)sb.st_size,
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
		    "<head-url>https://%s.s3.%s.amazonaws.com%s?%s</head-url>",
		    bucket, region, path, query) == -1)
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
		    "<get-url>https://%s.s3.%s.amazonaws.com%s?%s</get-url>",
		    bucket, region, path, query) == -1)
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
		    "<delete-url>https://%s.s3.%s.amazonaws.com%s?%s</delete-url>",
		    bucket, region, path, query) == -1)
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
	if (s3_put_loop(key_id, key_secret, region, bucket, path,
	    (uint8_t *)s, len)) {
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
	char * body;

	/* Sign request. */
	if (aws_sign_ec2_headers(key_id, key_secret, region, (uint8_t *)s,
	    strlen(s), &x_amz_content_sha256, &x_amz_date, &authorization)) {
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
	if ((errstr = sslreq(host, "443", CERTFILE, (uint8_t *)req, len,
	    resp, &resplen)) != NULL) {
		warnp("SSL request failed: %s", errstr);
		goto err4;
	}

	/* NUL-terminate the response. */
	resp[resplen] = '\0';

	/* EC2 API responses should not contain NUL bytes. */
	if (strlen((char *)resp) != resplen) {
		warnp("NUL byte in EC2 API response");
		goto err4;
	}

        /* Find the end of the first line. */
        pos = strcspn((char *)resp, "\r\n");

        /* Look for a "200" status on the first line. */
        if ((strstr((char *)resp, " 200 ") == NULL) ||
            (strstr((char *)resp, " 200 ") > (char *)&resp[pos])) {
		warnp("EC2 API request failed:\n%s\n", resp);
		goto err4;
	}

	/* Find the end of the headers. */
	if ((body = strstr((char *)resp, "\r\n\r\n")) == NULL) {
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
	if (asprintf(&url, "https://%s.s3.%s.amazonaws.com%s?%s",
	    bucket, region, manifest, query) == -1)
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

		/* Is the status something other than "active"? */
		if (strstr(resp, "<state>active</state>") == NULL) {
			/* Is there an <id> tag? */
			if ((volid = xmlextract(volume, "id")) != NULL) {
				/* We're done! */
				break;
			}
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
uploadraw(const char * diskimg, const char * region, const char * bucket,
    const char * key_id, const char * key_secret, uint64_t * imgsz)
{
	char * manifest;
	char * taskid;
	char * volume;
	char * snapshot;

	/* Upload disk image. */
	if ((manifest = uploadvolume(diskimg, region, bucket,
	    imgsz, key_id, key_secret)) == NULL) {
		warnp("Failure uploading disk image");
		goto err0;
	}

	/* Issue ImportVolume call. */
	if ((taskid = importvolume(region, bucket, manifest, *imgsz,
	    key_id, key_secret)) == NULL) {
		warnp("Failure importing disk image");
		goto err1;
	}

	/* Wait for the volume to be ready. */
	if ((volume = waitforimport(region, taskid,
	    key_id, key_secret)) == NULL) {
		warnp("Failure waiting for EBS volume");
		goto err2;
	}

	/* Create a snapshot. */
	if ((snapshot = createsnapshot(region, volume,
	    key_id, key_secret)) == NULL) {
		warnp("Failure creating snapshot");
		goto err3;
	}

	/* Wait for the snapshot to be ready. */
	if (waitforsnapshot(region, snapshot, key_id, key_secret)) {
		warnp("Failure waiting for EBS snapshot");
		goto err4;
	}

	/* Delete the volume now that it is snapshotted. */
	if (deletevolume(region, volume, key_id, key_secret)) {
		warnp("Failure deleting EBS volume");
		goto err4;
	}

	/* Return the snapshot ID. */
	return (snapshot);

err4:
	free(snapshot);
err3:
	free(volume);
err2:
	free(taskid);
err1:
	free(manifest);
err0:
	/* Failure! */
	return (NULL);
}

static char *
waitforimportsnapshot(const char * region, const char * taskid,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;
	char * snapshot;
	char * status;
	char * laststatus = NULL;

	/* Loop until we're finished. */
	do {
		/* Generate EC2 API request. */
		if (asprintf(&s,
		    "Action=DescribeImportSnapshotTasks&"
		    "ImportTaskId.1=%s&"
		    "Version=2016-11-15",
		    taskid) == -1)
			goto err0;

		/* Issue API request. */
		if ((resp = ec2_apicall_loop(key_id, key_secret, region, s))
		    == NULL)
			goto err1;

		/* Find <status> tag and stop looping if completed. */
		if ((status = xmlextract(resp, "status")) == NULL) {
			warnp("Could not find <status> in DescribeSnapshots response: %s", resp);
			goto err2;
		}
		if (strcmp(status, "completed") == 0)
			break;
		free(status);

		/* Look for a <statusMessage> tag. */
		if ((status = xmlextract(resp, "statusMessage")) == NULL) {
			warnp("Could not find <statusMessage> in DescribeImportSnapshotTasks response: %s", resp);
			goto err2;
		}

		/* Print status as appropriate. */
		printstatus("Creating snapshot", status, &laststatus);

		/* Free API request and response. */
		free(s);
		free(resp);

		/* Wait 10 seconds before making another API call. */
		sleep(10);
	} while(1);

	/* We're done! */
	fprintf(stderr, " done.\n");

	/* Find <SnapshotId> tag. */
	if ((snapshot = xmlextract(resp, "snapshotId")) == NULL) {
		warnp("Could not find <snapshotId> in DescribeImportSnapshotTasks response: %s", resp);
		goto err2;
	}

	/* Free API request and response. */
	free(s);
	free(resp);

	/* Free status and previous status message. */
	free(status);
	free(laststatus);

	/* Return snapshot ID. */
	return (snapshot);

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
uploadsnap(const char * fname, const char * imgfmt, const char * region,
    const char * bucket, const char * key_id, const char * key_secret,
    uint64_t * imgsz)
{
	uint8_t nonce[16];
	char noncehex[33];
	FILE * f;
	struct stat sb;
	size_t len;
	void * p;
	char * s;
	char * ec2req;
	char * resp;
	char * taskid;
	char * snapshot;

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

	/* Make sure it's not too big to be mapped into memory. */
	if ((sb.st_size < 0) ||
	    ((uintmax_t)(sb.st_size) > (uintmax_t)(SIZE_MAX))) {
		warn0("Disk image too big to map into memory: %s", fname);
		goto err1;
	}
	len = sb.st_size;
	*imgsz = sb.st_size;

	/* Map the file. */
	if ((p = mmap(NULL, len, PROT_READ, MAP_PRIVATE
#ifdef MAP_NOCORE
		| MAP_NOCORE
#endif
	    , fileno(f), 0)) == MAP_FAILED) {
		warnp("Could not map disk image");
		goto err1;
	}

	/* Construct an S3 object name. */
	if ((asprintf(&s, "/%s/snap.%s", noncehex, imgfmt)) == -1) {
		warnp("asprintf");
		goto err2;
	}

	/* Say what we're doing. */
	fprintf(stderr, "Uploading %s to\nhttp://%s.s3.amazonaws.com%s\n",
	    fname, bucket, s);

	/* Upload the disk image. */
	if (s3_put_loop(key_id, key_secret, region, bucket, s, p, len)) {
		warnp("Failed to upload disk image");
		goto err3;
	}

	/* Generate EC2 API request. */
	if (asprintf(&ec2req,
	    "Action=ImportSnapshot&"
	    "DiskContainer.Url=s3://%s%s&"
	    "Version=2016-11-15",
	    bucket, s) == -1)
		goto err3;

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, region, ec2req)) == NULL)
		goto err4;

	/* Extract the conversion task ID. */
	if ((taskid = xmlextract(resp, "importTaskId")) == NULL) {
		warnp("Could not find importTaskId in ImportSnapshot response:\n%s\n",
		    resp);
		goto err5;
	}

	/* Wait for the conversion task to complete. */
	if ((snapshot = waitforimportsnapshot(region, taskid,
	    key_id, key_secret)) == NULL)
		goto err6;

	/* Clean up. */
	free(taskid);
	free(resp);
	free(ec2req);
	free(s);
	munmap(p, len);
	fclose(f);

	/* Return snapshot ID. */
	return (snapshot);

err6:
	free(taskid);
err5:
	free(resp);
err4:
	free(ec2req);
err3:
	free(s);
err2:
	munmap(p, len);
err1:
	fclose(f);
err0:
	/* Failure! */
	return (NULL);
}

static char *
registerimage(const char * region, const char * snapshot, const char * name,
    const char * desc, const char * arch, int sriov, int ena,
    const char * key_id, const char * key_secret, uint64_t imgsz,
    const char * bootmode)
{
	char * nameenc;
	char * descenc;
	char * archenc;
	char * s;
	char * resp;
	char * ami;
	int rootsz;

	/* Compute default root disk size based on image size. */
	if (imgsz <= (uint64_t)(10) << 30)
		rootsz = 10;
	else if (imgsz <= (uint64_t)(1000) << 30)
		rootsz = (imgsz + (1 << 30) - 1) >> 30;
	else {
		warn0("Disk image exceeds 1000 GB!");
		goto err0;
	}

	/* Encode name and description strings. */
	if ((nameenc = rfc3986_encode(name)) == NULL)
		goto err0;
	if ((descenc = rfc3986_encode(desc)) == NULL)
		goto err1;
	if ((archenc = rfc3986_encode(arch)) == NULL)
		goto err2;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=RegisterImage&"
	    "Name=%s&"
	    "Description=%s&"
	    "Architecture=%s&"
	    "RootDeviceName=%%2Fdev%%2Fsda1&"
	    "VirtualizationType=hvm&"
	    "%s"
	    "%s"
	    "BlockDeviceMapping.1.DeviceName=%%2Fdev%%2Fsda1&"
	    "BlockDeviceMapping.1.Ebs.SnapshotId=%s&"
	    "BlockDeviceMapping.1.Ebs.VolumeType=gp2&"
	    "BlockDeviceMapping.1.Ebs.VolumeSize=%d&"
	    "BlockDeviceMapping.2.DeviceName=%%2Fdev%%2Fsdb&"
	    "BlockDeviceMapping.2.VirtualName=ephemeral0&"
	    "BlockDeviceMapping.3.DeviceName=%%2Fdev%%2Fsdc&"
	    "BlockDeviceMapping.3.VirtualName=ephemeral1&"
	    "BlockDeviceMapping.4.DeviceName=%%2Fdev%%2Fsdd&"
	    "BlockDeviceMapping.4.VirtualName=ephemeral2&"
	    "BlockDeviceMapping.5.DeviceName=%%2Fdev%%2Fsde&"
	    "BlockDeviceMapping.5.VirtualName=ephemeral3&"
	    "BootMode=%s&"
	    "Version=2016-11-15",
	    nameenc, descenc, archenc, sriov ? "SriovNetSupport=simple&" : "",
	    ena ? "EnaSupport=true&" : "",
	    snapshot, rootsz, bootmode) == -1)
		goto err3;

	/*
	 * Say what we're doing.  Include ... here because AMIs will usually
	 * be ready as soon as this API call returns, so there won't be any
	 * spinning in DescribeImages to produce dots.
	 */
	fprintf(stderr, "Registering AMI...");

	/* Issue API request. */
	if ((resp = ec2_apicall(key_id, key_secret, region, s)) == NULL)
		goto err4;

	/* Find <imageId> tag. */
	if ((ami = xmlextract(resp, "imageId")) == NULL) {
		warnp("Could not find <imageId> in RegisterImage response: %s", resp);
		goto err5;
	}

	/* Free API response. */
	free(resp);

	/* Free request and parts thereof. */
	free(s);
	free(archenc);
	free(descenc);
	free(nameenc);

	/* Return AMI. */
	return (ami);

err5:
	free(resp);
err4:
	free(s);
err3:
	free(archenc);
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

static int
makesnappublic(const char * region, const char * snapshot,
    const char * key_id, const char * key_secret)
{
	char * s;
	char * resp;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=ModifySnapshotAttribute&"
	    "SnapshotId=%s&"
	    "CreateVolumePermission.Add.1.Group=all&"
	    "Version=2014-09-01",
	    snapshot) == -1)
		goto err0;

	/* Issue API request. */
	if ((resp = ec2_apicall_loop(key_id, key_secret, region, s)) == NULL)
		goto err1;

	/* Make sure that we succeeded. */
	if (strstr(resp, "<return>true</return>") == NULL) {
		warnp("ModifySnapshotAttribute failed: %s", resp);
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

static int
ssm_store(const char * key_id, const char * key_secret,
    const char * ssm_name, const char * region, const char * ami)
{
	char * s;
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

	/* Construct SSM PutParameter request body. */
	if (asprintf(&s, "{"
	    "\"Name\":\"%s\","
	    "\"Value\":\"%s\","
	    "\"Type\":\"String\","
	    "\"DataType\":\"aws:ec2:image\","
	    "\"Overwrite\":true"
	    "}", ssm_name, ami) == -1)
		goto err0;

	/* Sign request. */
	if (aws_sign_ssm_headers(key_id, key_secret, region, "PutParameter",
	    (uint8_t *)s, strlen(s), &x_amz_content_sha256, &x_amz_date,
	    &authorization)) {
		warnp("Failed to sign SSM PutParameter request");
		goto err1;
	}

	/* Construct request and compute length. */
	if (asprintf(&req,
	    "POST / HTTP/1.0\r\n"
	    "Host: ssm.%s.amazonaws.com\r\n"
	    "X-Amz-Date: %s\r\n"
	    "X-Amz-Content-SHA256: %s\r\n"
	    "X-Amz-Target: AmazonSSM.PutParameter\r\n"
	    "Authorization: %s\r\n"
	    "Content-Length: %zu\r\n"
	    "Content-Type: application/x-amz-json-1.1\r\n"
	    "Connection: close\r\n"
	    "\r\n"
	    "%s",
	    region, x_amz_date, x_amz_content_sha256, authorization,
	    strlen(s), s) == -1)
		goto err2;
	len = strlen(req);

	/* Construct EC2 endpoint name. */
	if (asprintf(&host, "ssm.%s.amazonaws.com", region) == -1)
		goto err3;

	/* Allocate space for a 16 kB response plus a trailing NUL. */
	resplen = 16384;
	if ((resp = malloc(resplen + 1)) == NULL)
		goto err4;

	/* Send the request. */
	if ((errstr = sslreq(host, "443", CERTFILE, (uint8_t *)req, len,
	    resp, &resplen)) != NULL) {
		warnp("SSL request failed: %s", errstr);
		goto err5;
	}

	/* NUL-terminate the response. */
	resp[resplen] = '\0';

	/* EC2 API responses should not contain NUL bytes. */
	if (strlen((char *)resp) != resplen) {
		warnp("NUL byte in SSM API response");
		goto err5;
	}

        /* Find the end of the first line. */
        pos = strcspn((char *)resp, "\r\n");

        /* Look for a "200" status on the first line. */
        if ((strstr((char *)resp, " 200 ") == NULL) ||
            (strstr((char *)resp, " 200 ") > (char *)&resp[pos])) {
		warnp("SSM API request failed:\n%s\n", resp);
		goto err5;
	}

	/* If we got an HTTP 200, assume we succeeded. */

	/* Free response buffer. */
	free(resp);

	/* Free request buffers. */
	free(host);
	free(req);
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
	free(s);

	/* Success! */
	return (0);

err5:
	free(resp);
err4:
	free(host);
err3:
	free(req);
err2:
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static int
sns_publish(const char * key_id, const char * key_secret,
    const char * topicarn, const char * releaseversion,
    const char * imageversion,  const char * name, const char * arch,
    size_t nregions, char ** regions, char ** amis)
{
	char * msg_subject;
	char * msg_topicarn;
	STR message;
	char * msg_message;
	size_t i;
	char * s;
	char * region;
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
	char * body;

	/* Construct message subject. */
	if (asprintf(&msg_subject, "New %s AMIs", releaseversion) == -1)
		goto err0;
	if ((msg_subject = encodeamp(msg_subject)) == NULL)
		goto err0;

	/* Duplicate and encode Topic ARN. */
	if (asprintf(&msg_topicarn, "%s", topicarn) == -1)
		goto err1;
	if ((msg_topicarn = encodeamp(msg_topicarn)) == NULL)
		goto err1;

#define WRITE(a, b) do {				\
	if (str_append(a, b, strlen(b))) {		\
		str_free(a);				\
		goto err2;				\
	}						\
} while (0)

	/* Create an elastic string for the message XML. */
	if ((message = str_init(0)) == NULL)
		goto err2;
	WRITE(message, "{\n  \"v1\": {\n    \"ReleaseVersion\": \"");
	WRITE(message, releaseversion);
	WRITE(message, "\",\n    \"ImageVersion\": \"");
	WRITE(message, imageversion);
	WRITE(message, "\",\n    \"Regions\": {\n");
	for (i = 0; i < nregions; i++) {
		WRITE(message, "      \"");
		WRITE(message, regions[i]);
		WRITE(message, "\": [\n        {\n");
		WRITE(message, "          \"Name\": \"");
		WRITE(message, name);
		WRITE(message, "\",\n");
		WRITE(message, "          \"Architecture\": \"");
		WRITE(message, arch);
		WRITE(message, "\",\n");
		WRITE(message, "          \"ImageId\": \"");
		WRITE(message, amis[i]);
		WRITE(message, "\"\n        }\n      ]");
		if (i != nregions - 1) {
			WRITE(message, ",");
		}
		WRITE(message, "\n");
	}
	WRITE(message, "    }\n  }\n}");
	if (str_append(message, "\0", 1)) {
		str_free(message);
		goto err2;
	}
#undef WRITE

	/* Export string and encode. */
	if (str_export(message, &msg_message, &len)) {
		str_free(message);
		goto err2;
	}

	/* Construct request. */
	if (asprintf(&s, "Action=Publish&Message=%s&"
	    "Subject=%s&TopicArn=%s&Version=2010-03-31",
	    msg_message, msg_subject, msg_topicarn) == -1)
		goto err3;

	/*
	 * Figure out which region to make the request to.  SNS topic ARNs
	 * always start with "arn:aws:sns:<region>:" so we can skip the
	 * first 12 bytes and then stop at the next ':'.
	 */
	if ((region = strdup(&topicarn[12])) == NULL)
		goto err4;
	region[strcspn(region, ":")] = '\0';

	/* Sign request. */
	if (aws_sign_sns_headers(key_id, key_secret, region, (uint8_t *)s,
	    strlen(s), &x_amz_content_sha256, &x_amz_date, &authorization)) {
		warnp("Failed to sign SNS POST request");
		goto err5;
	}

	/* Construct request and compute length. */
	if (asprintf(&req,
	    "POST / HTTP/1.0\r\n"
	    "Host: sns.%s.amazonaws.com\r\n"
	    "X-Amz-Date: %s\r\n"
	    "X-Amz-Content-SHA256: %s\r\n"
	    "Authorization: %s\r\n"
	    "Content-Length: %zu\r\n"
	    "Content-Type: application/x-www-form-urlencoded\r\n"
	    "Connection: close\r\n"
	    "\r\n"
	    "%s",
	    region, x_amz_date, x_amz_content_sha256, authorization,
	    strlen(s), s) == -1)
		goto err6;
	len = strlen(req);

	/* Construct SNS endpoint name. */
	if (asprintf(&host, "sns.%s.amazonaws.com", region) == -1)
		goto err7;

	/* Allocate space for a 16 kB response plus a trailing NUL. */
	resplen = 16384;
	if ((resp = malloc(resplen + 1)) == NULL)
		goto err8;

	/* Send the request. */
	if ((errstr = sslreq(host, "443", CERTFILE, (uint8_t *)req, len,
	    resp, &resplen)) != NULL) {
		warnp("SSL request failed: %s", errstr);
		goto err9;
	}

	/* NUL-terminate the response. */
	resp[resplen] = '\0';

	/* SNS API responses should not contain NUL bytes. */
	if (strlen((char *)resp) != resplen) {
		warnp("NUL byte in SNS API response");
		goto err9;
	}

        /* Find the end of the first line. */
        pos = strcspn((char *)resp, "\r\n");

        /* Look for a "200" status on the first line. */
        if ((strstr((char *)resp, " 200 ") == NULL) ||
            (strstr((char *)resp, " 200 ") > (char *)&resp[pos])) {
		warnp("SNS API request failed:\n%s\n", resp);
		goto err9;
	}

	/* Find the end of the headers. */
	if ((body = strstr((char *)resp, "\r\n\r\n")) == NULL) {
		warnp("Bad SNS API response received:\n%s\n", resp);
		goto err9;
	}

	/* Skip to the start of the response body. */
	body = &body[4];

	/* Make sure there's a MessageId. */
	if (strstr(body, "<MessageId>") == NULL) {
		warnp("SNS API call failed?\n%s\n", body);
		goto err9;
	}

	/* Free response buffer. */
	free(resp);

	/* Free request buffers. */
	free(host);
	free(req);
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
	free(region);
	free(s);
	free(msg_message);
	free(msg_topicarn);
	free(msg_subject);

	/* Success! */
	return (0);

err9:
	free(resp);
err8:
	free(host);
err7:
	free(req);
err6:
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
err5:
	free(region);
err4:
	free(s);
err3:
	free(msg_message);
err2:
	free(msg_topicarn);
err1:
	free(msg_subject);
err0:
	/* Failure! */
	return (-1);
}

static void
usage(void)
{

	fprintf(stderr, "usage: bsdec2-image-upload [--public]"
	    " [--publicamis] [--allregions] [--publicsnap]"
	    " [--ssm-name <path>] [--sriov] [--ena] [--arm64]"
	    " [--vhd]"
	    " %s %s %s %s %s %s [%s %s %s]\n",
	    "<disk image>", "<name>", "<description>",
	    "<region>", "<bucket>", "<AWS keyfile>",
	    "<topicarn>", "<releaseversion>", "<imageversion>");
	exit(1);
}

int
main(int argc, char * argv[])
{
	const char * ch;
	int publicamis = 0;
	int allregions = 0;
	int publicsnap = 0;
	int sriov = 0;
	int ena = 0;
	int rawdisk = 1;
	const char * diskimg;
	const char * name;
	const char * desc;
	const char * region;
	const char * bucket;
	const char * keyfile;
	const char * topicarn = NULL;
	const char * releaseversion;
	const char * imageversion;
	const char * arch = "x86_64";
	const char * ssm_name = NULL;
	const char * imgfmt = NULL;
	const char * bootmode = NULL;
	char * key_id;
	char * key_secret;
	char ** regions;
	size_t nregions;
	char * snapshot;
	char * ami;
	char ** amis;
	size_t i;
	uint64_t imgsz;

	WARNP_INIT;

	/* Parse command line. */
	while ((ch = GETOPT(argc, argv)) != NULL) {
		GETOPT_SWITCH(ch) {
		GETOPT_OPT("--public"):
			publicamis = 1;
			allregions = 1;
			break;
		GETOPT_OPT("--publicsnap"):
			publicsnap = 1;
			break;
		GETOPT_OPT("--publicamis"):
			publicamis = 1;
			break;
		GETOPT_OPT("--allregions"):
			allregions = 1;
			break;
		GETOPT_OPT("--sriov"):
			sriov = 1;
			break;
		GETOPT_OPT("--ena"):
			ena = 1;
			break;
		GETOPT_OPT("--arm64"):
			arch = "arm64";
			break;
		GETOPT_OPTARG("--ssm-name"):
			ssm_name = optarg;
			break;
		GETOPT_OPT("--uefi"):
			bootmode = "uefi";
			break;
		GETOPT_OPT("--vhd"):
			imgfmt = "vhd";
			rawdisk = 0;
			break;
		GETOPT_OPT("-v"):
			fprintf(stderr, "bsdec2-image-upload @VERSION@\n");
			exit(0);
		GETOPT_MISSING_ARG:
			fprintf(stderr, "missing argument\n");
			/* FALLTHROUGH */
		GETOPT_DEFAULT:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Check number of arguments and assign to variables. */
	switch (argc) {
	case 9:
		topicarn = argv[6];
		releaseversion = argv[7];
		imageversion = argv[8];
		/* FALLTHROUGH */
	case 6:
		diskimg = argv[0];
		name = argv[1];
		desc = argv[2];
		region = argv[3];
		bucket = argv[4];
		keyfile = argv[5];
		break;
	default:
		/* Wrong number of arguments. */
		usage();
	}

	/* Set default boot mode if not specified. */
	if (bootmode == NULL) {
		if (strcmp(arch, "arm64") == 0)
			bootmode = "uefi";
		else
			bootmode = "legacy-bios";
	}

	/* Load AWS keys. */
	if (aws_readkeys(keyfile, &key_id, &key_secret)) {
		warnp("Cannot read AWS keys");
		exit(1);
	}

	/* Ignore SIGPIPE. */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		warnp("signal(SIGPIPE)");
		exit(1);
	}

	/* Get list of AWS regions. */
	if (allregions) {
		if (getregionlist(key_id, key_secret, region, &regions,
		    &nregions)) {
			warnp("Failure getting list of AWS regions");
			exit(1);
		}
	} else {
		/* We're only using one region. */
		if ((regions = malloc(sizeof(char *))) == NULL) {
			warnp("malloc");
			exit(1);
		}
		if ((regions[0] = strdup(region)) == NULL) {
			warnp("strdup");
			exit(1);
		}
		nregions = 1;
	}

	/* If we have a raw disk image, create a volume and snapshot it. */
	if (rawdisk) {
		if ((snapshot = uploadraw(diskimg, region, bucket,
		    key_id, key_secret, &imgsz)) == NULL)
			exit(1);
	} else {
		if ((snapshot = uploadsnap(diskimg, imgfmt, region, bucket,
		    key_id, key_secret, &imgsz)) == NULL)
			exit(1);
	}

	/* Mark snapshot as public. */
	if (publicsnap) {
		fprintf(stderr, "Marking %s in %s as public...", snapshot, region);
		if (makesnappublic(region, snapshot, key_id, key_secret)) {
			warnp("Error marking EBS snapshot as public");
			exit(1);
		}
		fprintf(stderr, " done.\n");
	}

	/* Register an image. */
	if ((ami = registerimage(region, snapshot, name, desc, arch, sriov,
	    ena, key_id, key_secret, imgsz, bootmode)) == NULL) {
		warnp("Failure registering AMI");
		exit(1);
	}

	/* Wait for the AMI to be ready. */
	if (waitforami(region, ami, key_id, key_secret)) {
		warnp("Failure waiting for AMI");
		exit(1);
	}

	/* Allocate array of AMI names. */
	if ((amis = malloc(nregions * sizeof(char *))) == NULL) {
		warnp("malloc");
		exit(1);
	}

	/* Copy images into the regions. */
	if (allregions)
		fprintf(stderr, "Copying AMI to regions:");
	for (i = 0; i < nregions; i++) {
		/* Don't copy to the region where we built the image. */
		if (strcmp(regions[i], region) == 0) {
			if ((amis[i] = strdup(ami)) == NULL) {
				warnp("strdup");
				exit(1);
			}
			continue;
		}

		fprintf(stderr, " %s", regions[i]);
		if ((amis[i] = copyimage(region, ami, regions[i],
		    key_id, key_secret)) == NULL) {
			warnp("Error copying AMI to region %s", regions[i]);
			exit(1);
		}
	}
	if (allregions)
		fprintf(stderr, ".\n");

	/* Wait for the copying to complete. */
	for (i = 0; i < nregions; i++) {
		if (strcmp(regions[i], region) == 0)
			continue;

		/* Wait for AMI to finish copying. */
		fprintf(stderr, "Waiting for AMI copying to %s...", regions[i]);
		if (waitforami(regions[i], amis[i], key_id, key_secret)) {
			warnp("Failure waiting for AMI");
			exit(1);
		}
	}

	/* Mark images as public. */
	if (publicamis) {
		fprintf(stderr, "Marking images as public...");
		for (i = 0; i < nregions; i++) {
			if (makepublic(regions[i], amis[i],
			    key_id, key_secret)) {
				warnp("Error marking AMI as public");
				exit(1);
			}
		}
		fprintf(stderr, " done.\n");
	}

	/* Record AMI IDs in SSM Parameter Store. */
	if (ssm_name) {
		fprintf(stderr, "Storing AMI Ids in SSM Parameter Store...");
		for (i = 0; i < nregions; i++) {
			if (ssm_store(key_id, key_secret, ssm_name,
			    regions[i], amis[i])) {
				warnp("Error storing AMI Id for region %s",
				    regions[i]);
				exit(1);
			}
		}
		fprintf(stderr, " done.\n");
	}

	/* Print the list of AMIs. */
	for (i = 0; i < nregions; i++)
		printf("Created AMI in %s region: %s\n", regions[i], amis[i]);

	/* Try to send an SNS notification if desired. */
	if (topicarn) {
		if (sns_publish(key_id, key_secret, topicarn,
		    releaseversion, imageversion, name, arch,
		    nregions, regions, amis)) {
			warnp("Failed to send SNS notification");
		}
	}

	return (0);
}
