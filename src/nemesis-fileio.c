/*
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-fileio.c (nemesis file utility functions)
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(WIN32)
#include <pcap.h>
#include <fcntl.h>
#endif
#include <unistd.h>
#if defined(HAVE_ERRNO_H) || defined(WIN32)
#include <errno.h>
#endif
#include "nemesis.h"

#if 0
char *pcap_outfile;		/* pcap output file name */
#endif

/**
 * Reads a user supplied file or stdin into buf for use in building packet 
 * payloads or adding options to IP or TCP headers.
 *
 * @param file pointer to filename to open
 * @param mode switch controlling mode of operation (for error reporting only)
 * @param buf pointer to allocated payload/options buf
 * @param len maximum size, in bytes, of @param buf
 *
 * @return number of bytes read on success, -1 on failure
 **/
static int nemesis_readfile(const char *file, const uint32_t mode, uint8_t *buf, const size_t len)
{
	ssize_t num;
	FILE *fp = NULL;
	int   fd = -1;
#if defined(WIN32)
	TCHAR WinErrBuf[WINERRBUFFSIZE];
#endif

	if (!buf) {
		fprintf(stderr, "ERROR: %s readfile() buffer unitialized.\n", mode ? "Payload" : "Options");
		return -1;
	}

	if (!strncmp(file, "-", 1)) {
		fp = stdin;
		fd = fileno(fp);
	} else if ((fd = open(file, O_RDONLY)) < 0) {
#if !defined(WIN32)
		fprintf(stderr, "ERROR: Unable to open %s file %s: %s\n",
			mode ? "Payload" : "Options", file, strerror(errno));
#else
		if (winstrerror(WinErrBuf, sizeof(WinErrBuf)) < 0)
			return -1;

		fprintf(stderr, "ERROR: Unable to open %s file %s:\n%s\n",
		        mode ? "Payload" : "Options", file, WinErrBuf);
#endif
		return -1;
	}

	/* read() can return negative values on successful reads, test for -1 */
	num = read(fd, buf, len);
	if (num == -1) {
#if !defined(WIN32)
		fprintf(stderr, "ERROR: Unable to read %s file %s: %s\n",
		        mode ? "Payload" : "Options", file, strerror(errno));
#else
		if (winstrerror(WinErrBuf, sizeof(WinErrBuf)) < 0)
			return -1;

		fprintf(stderr, "ERROR: Unable to read %s file %s:\n%s\n",
		        mode ? "Payload" : "Options", file, WinErrBuf);
#endif
	}

	if (strncmp(file, "-", 1) && fd != -1)
		close(fd);

	return num;
}

/**
 * Wrapper for calloc() and nemesis_readfile() for building packet payloads, 
 * IP and TCP options from files.
 *
 * @param sz maximum number of bytes to read from file or stdin
 * @param fd pointer to struct file structure
 * @param file pointer to filename to open
 * @param mode switch controlling mode of operation (for error reporting only)
 *
 * @return 0 on sucess, -1 on failure
 **/
int builddatafromfile(const size_t sz, struct file *fd, const char *file, const uint32_t mode)
{
	fd->file_buf = calloc(sz, sizeof(uint8_t));
	if (!fd->file_buf) {
		if (mode == PAYLOADMODE)
			perror("ERROR: Unable to allocate packet payload memory");
		else
			perror("ERROR: Unable to allocate packet options memory");

		return -1;
	}

	fd->file_len = nemesis_readfile(file, mode == PAYLOADMODE, fd->file_buf, sz);
	if (fd->file_len < 0) {
		if (mode == PAYLOADMODE)
			fprintf(stderr, "ERROR: Unable to read any payload data.\n");
		else
			fprintf(stderr, "ERROR: Unable to read any options data.\n");

		return -1;
	}

	return 0;
}
