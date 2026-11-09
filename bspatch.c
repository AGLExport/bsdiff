/*-
 * Copyright 2003-2005 Colin Percival
 * Copyright 2012 Matthew Endsley
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "bspatch.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int bspatch(int64_t oldsize, int64_t newsize, struct bspatch_stream *stream)
{
	uint8_t *buffer = NULL;
	uint8_t *oldbuffer = NULL;
	uint8_t record[24];
	int64_t ctrl[3], oldpos = 0, newpos = 0, end, next;
	int64_t length, chunk, start, stop, position, i;
	int channel, result = -1, status;

	if (oldsize < 0 || newsize < 0 || stream == NULL || stream->read == NULL ||
		stream->old_read == NULL || stream->write == NULL) {
		return -1;
	}
	buffer = malloc(PATCH_BUFFER_SIZE);
	oldbuffer = malloc(PATCH_BUFFER_SIZE);
	if (buffer == NULL || oldbuffer == NULL) {
		goto cleanup;
	}
	while (newpos < newsize) {
		status = stream->read(stream, PATCH_CTRL, record, sizeof(record));
		if (status != 0) {
			goto cleanup;
		}
		for (i = 0; i < 3; i++) {
			ctrl[i] = patch_decode(record + 8 * i);
		}
		if (ctrl[0] < 0 || ctrl[1] < 0 || ctrl[0] > newsize - newpos ||
			ctrl[1] > newsize - newpos - ctrl[0]) {
			goto cleanup;
		}
		status = patch_add(oldpos, ctrl[0], &end);
		if (status != 0) {
			goto cleanup;
		}
		status = patch_add(end, ctrl[2], &next);
		if (status != 0) {
			goto cleanup;
		}
		for (channel = PATCH_DIFF; channel <= PATCH_EXTRA; channel++) {
			length = ctrl[channel - PATCH_DIFF];
			while (length > 0) {
				chunk = length < PATCH_BUFFER_SIZE ? length : PATCH_BUFFER_SIZE;
				status = stream->read(stream, channel, buffer, (int)chunk);
				if (status != 0) {
					goto cleanup;
				}
				if (channel == PATCH_DIFF) {
					/* Clip the old range without negating INT64_MIN. */
					start = 0;
					if (oldpos < 0) {
						start = oldpos < -chunk ? chunk : -oldpos;
					}
					stop = chunk;
					if (oldpos >= oldsize) {
						stop = 0;
					} else if (oldpos >= 0 && oldsize - oldpos < stop) {
						stop = oldsize - oldpos;
					} else if (oldpos < 0 && oldsize < chunk - start) {
						stop = start + oldsize;
					}
					if (stop > start) {
						position = oldpos + start;
						status = stream->old_read(stream, position, oldbuffer, (int)(stop - start));
						if (status != 0) {
							goto cleanup;
						}
						for (i = start; i < stop; i++) {
							buffer[i] += oldbuffer[i - start];
						}
					}
					oldpos += chunk; /* Checked for the entire interval above. */
				}
				status = stream->write(stream, buffer, (int)chunk);
				if (status != 0) {
					goto cleanup;
				}
				newpos += chunk;
				length -= chunk;
			}
		}
		oldpos = next;
	}
	result = 0;
cleanup:
	free(oldbuffer);
	free(buffer);
	return result;
}

#if defined(BSPATCH_EXECUTABLE)
#include <stdio.h>

int main(int argc, char *argv[])
{
	int result;

	if (argc != 5) {
		fprintf(stderr, "usage: %s oldfile newfile prefix unpackdir\n", argv[0]);
		return 1;
	}
	result = bspatch_files(argv[1], argv[2], argv[3], argv[4]);
	if (result != 0) {
		fprintf(stderr, "bspatch: patch validation or application failed\n");
		return 1;
	}
	return 0;
}
#endif
