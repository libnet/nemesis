/*
 * $Id: nemesis-fileio.c,v 1.1.1.1 2003/10/31 21:29:36 jnathan Exp $
 *
 * THE NEMESIS PROJECT
 * Copyright (C) 2002, 2003 Jeff Nathan <jeff@snort.org>
 *
 * nemesis-functions.c (nemesis utility functions)
 *
 */

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(WIN32)
    #include <pcap.h>
#endif
#include <unistd.h>
#if defined(HAVE_ERRNO_H) || defined(WIN32)
    #include <errno.h>
#endif
#include "nemesis.h"

#if 0
char *pcap_outfile;     /* pcap output file name */
#endif

static int nemesis_readfile(u_int8_t *, const char *, const size_t, 
        const u_int32_t);

/**
 * Reads a user supplied file or stdin into memory for use in building packet 
 * payloads or adding options to IP or TCP headers.
 *
 * @param memory pointer to allocated payload/options memory
 * @param file pointer to filename to open
 * @param maxsize maximum number of bytes to read from file or stdin
 * @param mode switch controlling mode of operation (for error reporting only)
 *
 * @return number of bytes read on success, -1 on failure
 **/
static int nemesis_readfile(u_int8_t *memory, const char *file, 
        const size_t maxsize, const u_int32_t mode)
{
    int fd = -1, bytesread = 0;
    FILE *fp = NULL;
#if defined(WIN32)
    TCHAR WinErrBuf[WINERRBUFFSIZE];
#endif

    if (memory == NULL)
    {
        fprintf(stderr, "ERROR: %s readfile() memory unitialized.\n", 
                (mode == PAYLOADMODE ? "Payload" : "Options"));
        return -1;
    }

    if (!strncmp(file, "-", 1))
    {
        fp = stdin;
        fd = fileno(fp);
    }
    else if ((fd = open(file, O_RDONLY)) < 0)
    {
#if !defined(WIN32)
        fprintf(stderr, "ERROR: Unable to open %s file: %s. %s\n",
                (mode == PAYLOADMODE) ? "Payload" : "Options", file, 
                strerror(errno));
#else
        if (winstrerror(WinErrBuf, sizeof(WinErrBuf)) < 0)
            return -1;
        else
        {
            fprintf(stderr, "ERROR: Unable to open %s file: %s.\n%s\n",
                    (mode == PAYLOADMODE) ? "Payload" : "Options", file, 
                    WinErrBuf);
        }
#endif
        return -1;
    }

    /* read() can return negative values on successful reads, test for -1 */
    if ((bytesread = read(fd, (void *)memory, maxsize)) == -1)
    {
#if !defined(WIN32)
        fprintf(stderr, "ERROR: Unable to read %s file: %s. %s\n",
                (mode == PAYLOADMODE) ? "Payload" : "Options", file, 
                strerror(errno));
#else
        if (winstrerror(WinErrBuf, sizeof(WinErrBuf)) < 0)
            return -1;
        else
        {
            fprintf(stderr, "ERROR: Unable to read %s file: %s.\n%s\n",
                    (mode == PAYLOADMODE) ? "Payload" : "Options", file, 
                    WinErrBuf);
        }
#endif
        return -1;
    }
    else
    {
        if (strncmp(file, "-", 1))
            close(fd);
    }
    return bytesread;
}


/**
 * Wrapper for calloc() and nemesis_readfile() for building packet payloads, 
 * IP and TCP options from files.
 *
 * @param buffsize maximum number of bytes to read from file or stdin
 * @param memory pointer to FileData structure
 * @param file pointer to filename to open
 * @param mode switch controlling mode of operation (for error reporting only)
 *
 * @return 0 on sucess, -1 on failure
 **/
int builddatafromfile(const size_t buffsize, FileData *memory, 
        const char *file, const u_int32_t mode)
{
    if ((memory->file_mem = (u_int8_t *)calloc(buffsize, 
            sizeof(u_int8_t))) == NULL)
    {
        if (mode == PAYLOADMODE)
            perror("ERROR: Unable to allocate packet payload memory");
        else
            perror("ERROR: Unable to allocate packet options memory");

        return -1;
    }

    if ((memory->file_s = nemesis_readfile(memory->file_mem, file, buffsize, 
            (mode == PAYLOADMODE ? PAYLOADMODE : OPTIONSMODE))) < 0)
    {
        if (mode == PAYLOADMODE)
            fprintf(stderr, "ERROR: Unable to read any payload data.\n");
        else
            fprintf(stderr, "ERROR: Unable to read any options data.\n");

        return -1;
    }

    return 0;
}
