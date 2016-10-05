PROG=	bsdec2-image-upload
SRCS=	main.c
NO_MAN	?=	yes
WARNS	?=	3
BINDIR	?=	/usr/local/bin
LDADD	+=	-lcrypto -lssl

# Fundamental algorithms
.PATH.c	:	libcperciva/alg
SRCS	+=	sha256.c
IDIRS	+=	-I libcperciva/alg

# Data structures
.PATH.c	:	libcperciva/datastruct
SRCS	+=	elasticarray.c
IDIRS	+=	-I libcperciva/datastruct

# Utility functions
.PATH.c	:	libcperciva/util
SRCS	+=	asprintf.c
SRCS	+=	entropy.c
SRCS	+=	hexify.c
SRCS	+=	insecure_memzero.c
SRCS	+=	rfc3986.c
SRCS	+=	warnp.c
IDIRS	+=	-I libcperciva/util

# AWS request signing
.PATH	:	lib/aws
SRCS	+=	aws_sign.c
IDIRS	+=	-I lib/aws

# SSL requests
.PATH	:	lib/util
SRCS	+=	sslreq.c
IDIRS	+=	-I lib/util

CFLAGS	+=	-g
CFLAGS	+=	${IDIRS}

.include <bsd.prog.mk>
