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

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "patchio-private.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "bsdiff.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static void split(int64_t *I, int64_t *V, int64_t start, int64_t len, int64_t h)
{
	int64_t i, j, k, x, tmp, jj, kk;

	if (len < 16) {
		for (k = start; k < start + len; k += j) {
			j = 1;
			x = V[I[k] + h];
			for (i = 1; k + i < start + len; i++) {
				if (V[I[k + i] + h] < x) {
					x = V[I[k + i] + h];
					j = 0;
				}
				if (V[I[k + i] + h] == x) {
					tmp = I[k + j];
					I[k + j] = I[k + i];
					I[k + i] = tmp;
					j++;
				}
			}
			for (i = 0; i < j; i++) {
				V[I[k + i]] = k + j - 1;
			}
			if (j == 1) {
				I[k] = -1;
			}
		}
		return;
	}

	x = V[I[start + len / 2] + h];
	jj = 0;
	kk = 0;
	for (i = start; i < start + len; i++) {
		if (V[I[i] + h] < x) {
			jj++;
		}
		if (V[I[i] + h] == x) {
			kk++;
		}
	}
	jj += start;
	kk += jj;

	i = start;
	j = 0;
	k = 0;
	while (i < jj) {
		if (V[I[i] + h] < x) {
			i++;
		} else if (V[I[i] + h] == x) {
			tmp = I[i];
			I[i] = I[jj + j];
			I[jj + j] = tmp;
			j++;
		} else {
			tmp = I[i];
			I[i] = I[kk + k];
			I[kk + k] = tmp;
			k++;
		}
	}

	while (jj + j < kk) {
		if (V[I[jj + j] + h] == x) {
			j++;
		} else {
			tmp = I[jj + j];
			I[jj + j] = I[kk + k];
			I[kk + k] = tmp;
			k++;
		}
	}

	if (jj > start) {
		split(I, V, start, jj - start, h);
	}

	for (i = 0; i < kk - jj; i++) {
		V[I[jj + i]] = kk - 1;
	}
	if (jj == kk - 1) {
		I[jj] = -1;
	}

	if (start + len > kk) {
		split(I, V, kk, start + len - kk, h);
	}
}

static void qsufsort(int64_t *I, int64_t *V, const uint8_t *old, int64_t oldsize)
{
	int64_t buckets[256];
	int64_t i, h, len;

	for (i = 0; i < 256; i++) {
		buckets[i] = 0;
	}
	for (i = 0; i < oldsize; i++) {
		buckets[old[i]]++;
	}
	for (i = 1; i < 256; i++) {
		buckets[i] += buckets[i - 1];
	}
	for (i = 255; i > 0; i--) {
		buckets[i] = buckets[i - 1];
	}
	buckets[0] = 0;

	for (i = 0; i < oldsize; i++) {
		I[++buckets[old[i]]] = i;
	}
	I[0] = oldsize;
	for (i = 0; i < oldsize; i++) {
		V[i] = buckets[old[i]];
	}
	V[oldsize] = 0;
	for (i = 1; i < 256; i++) {
		if (buckets[i] == buckets[i - 1] + 1) {
			I[buckets[i]] = -1;
		}
	}
	I[0] = -1;

	for (h = 1; I[0] != -(oldsize + 1); h += h) {
		len = 0;
		for (i = 0; i < oldsize + 1;) {
			if (I[i] < 0) {
				len -= I[i];
				i -= I[i];
			} else {
				if (len) {
					I[i - len] = -len;
				}
				len = V[I[i]] + 1 - i;
				split(I, V, i, len, h);
				i += len;
				len = 0;
			}
		}
		if (len) {
			I[i - len] = -len;
		}
	}

	for (i = 0; i < oldsize + 1; i++) {
		I[V[i]] = i;
	}
}

static int64_t matchlen(const uint8_t *old, int64_t oldsize, const uint8_t *new, int64_t newsize)
{
	int64_t i;

	for (i = 0; (i < oldsize) && (i < newsize); i++) {
		if (old[i] != new[i]) {
			break;
		}
	}

	return i;
}

static int64_t search(const int64_t *I, const uint8_t *old, int64_t oldsize, const uint8_t *new,
	int64_t newsize, int64_t st, int64_t en, int64_t *pos)
{
	int64_t x, y;
	int result;

	if (en - st < 2) {
		x = matchlen(old + I[st], oldsize - I[st], new, newsize);
		y = matchlen(old + I[en], oldsize - I[en], new, newsize);

		if (x > y) {
			*pos = I[st];
			return x;
		} else {
			*pos = I[en];
			return y;
		}
	}

	x = st + (en - st) / 2;
	result = memcmp(old + I[x], new, MIN(oldsize - I[x], newsize));
	if (result < 0) {
		return search(I, old, oldsize, new, newsize, x, en, pos);
	} else {
		return search(I, old, oldsize, new, newsize, st, x, pos);
	}
}

static void offtout(int64_t x, uint8_t *buf)
{
	int64_t y;

	if (x < 0) {
		y = -x;
	} else {
		y = x;
	}

	buf[0] = y % 256;
	y -= buf[0];
	y = y / 256;
	buf[1] = y % 256;
	y -= buf[1];
	y = y / 256;
	buf[2] = y % 256;
	y -= buf[2];
	y = y / 256;
	buf[3] = y % 256;
	y -= buf[3];
	y = y / 256;
	buf[4] = y % 256;
	y -= buf[4];
	y = y / 256;
	buf[5] = y % 256;
	y -= buf[5];
	y = y / 256;
	buf[6] = y % 256;
	y -= buf[6];
	y = y / 256;
	buf[7] = y % 256;

	if (x < 0) {
		buf[7] |= 0x80;
	}
}

static int writedata(struct bsdiff_stream *stream, int channel, const void *buffer, int64_t length)
{
	const uint8_t *data = buffer;
	int result;
	int chunk;

	while (length > 0) {
		chunk = (int)MIN(length, PATCH_BUFFER_SIZE);
		result = stream->write(stream, channel, data, chunk);
		if (result != 0) {
			return -1;
		}
		data += chunk;
		length -= chunk;
	}
	return 0;
}

struct bsdiff_request
{
	const uint8_t *old;
	int64_t oldsize;
	const uint8_t *new;
	int64_t newsize;
	struct bsdiff_stream *stream;
	int64_t *I;
	uint8_t *buffer;
};

static int bsdiff_internal(const struct bsdiff_request req)
{
	int64_t *I, *V;
	int64_t scan, pos, len;
	int64_t lastscan, lastpos, lastoffset;
	int64_t oldscore, scsc;
	int64_t s, Sf, lenf, Sb, lenb;
	int64_t overlap, Ss, lens;
	int64_t i;
	uint8_t *buffer;
	uint8_t buf[8 * 3];
	int write_result;
	int64_t offset, chunk, extra;

	V = req.stream->malloc((req.oldsize + 1) * sizeof(int64_t));
	if (V == NULL) {
		return -1;
	}
	I = req.I;

	qsufsort(I, V, req.old, req.oldsize);
	req.stream->free(V);

	buffer = req.buffer;

	/* Compute the differences, writing ctrl as we go */
	scan = 0;
	len = 0;
	pos = 0;
	lastscan = 0;
	lastpos = 0;
	lastoffset = 0;
	while (scan < req.newsize) {
		oldscore = 0;

		for (scsc = scan += len; scan < req.newsize; scan++) {
			len = search(
				I, req.old, req.oldsize, req.new + scan, req.newsize - scan, 0, req.oldsize, &pos);

			for (; scsc < scan + len; scsc++) {
				if ((scsc + lastoffset >= 0) && (scsc + lastoffset < req.oldsize) &&
					(req.old[scsc + lastoffset] == req.new[scsc])) {
					oldscore++;
				}
			}

			if (((len == oldscore) && (len != 0)) || (len > oldscore + 8)) {
				break;
			}

			if ((scan + lastoffset >= 0) && (scan + lastoffset < req.oldsize) &&
				(req.old[scan + lastoffset] == req.new[scan])) {
				oldscore--;
			}
		}

		if ((len != oldscore) || (scan == req.newsize)) {
			s = 0;
			Sf = 0;
			lenf = 0;
			for (i = 0; (lastscan + i < scan) && (lastpos + i < req.oldsize);) {
				if (req.old[lastpos + i] == req.new[lastscan + i]) {
					s++;
				}
				i++;
				if (s * 2 - i > Sf * 2 - lenf) {
					Sf = s;
					lenf = i;
				}
			}

			lenb = 0;
			if (scan < req.newsize) {
				s = 0;
				Sb = 0;
				for (i = 1; (scan >= lastscan + i) && (pos >= i); i++) {
					if (req.old[pos - i] == req.new[scan - i]) {
						s++;
					}
					if (s * 2 - i > Sb * 2 - lenb) {
						Sb = s;
						lenb = i;
					}
				}
			}

			if (lastscan + lenf > scan - lenb) {
				overlap = (lastscan + lenf) - (scan - lenb);
				s = 0;
				Ss = 0;
				lens = 0;
				for (i = 0; i < overlap; i++) {
					if (req.new[lastscan + lenf - overlap + i] ==
						req.old[lastpos + lenf - overlap + i]) {
						s++;
					}
					if (req.new[scan - lenb + i] == req.old[pos - lenb + i]) {
						s--;
					}
					if (s > Ss) {
						Ss = s;
						lens = i + 1;
					}
				}

				lenf += lens - overlap;
				lenb -= lens;
			}

			offtout(lenf, buf);
			offtout((scan - lenb) - (lastscan + lenf), buf + 8);
			offtout((pos - lenb) - (lastpos + lenf), buf + 16);

			/* Write control data */
			write_result = writedata(req.stream, PATCH_CTRL, buf, sizeof(buf));
			if (write_result != 0) {
				return -1;
			}

			/* Calculate diff in bounded chunks; extra comes directly from new. */
			for (offset = 0; offset < lenf; offset += chunk) {
				chunk = MIN(lenf - offset, PATCH_BUFFER_SIZE);
				for (i = 0; i < chunk; i++) {
					buffer[i] = req.new[lastscan + offset + i] - req.old[lastpos + offset + i];
				}
				write_result = writedata(req.stream, PATCH_DIFF, buffer, chunk);
				if (write_result != 0) {
					return -1;
				}
			}
			extra = (scan - lenb) - (lastscan + lenf);
			write_result = writedata(req.stream, PATCH_EXTRA, req.new + lastscan + lenf, extra);
			if (write_result != 0) {
				return -1;
			}

			lastscan = scan - lenb;
			lastpos = pos - lenb;
			lastoffset = pos - scan;
		}
	}

	return 0;
}

int bsdiff(const uint8_t *old, int64_t oldsize, const uint8_t *new, int64_t newsize,
	struct bsdiff_stream *stream)
{
	int result;
	struct bsdiff_request req;

	/* The sorter doubles lengths and scores; reserve signed arithmetic headroom. */
	if (oldsize < 0 || newsize < 0 || oldsize > (INT64_MAX - 1) / 2 ||
		newsize > (INT64_MAX - 1) / 2 || (uint64_t)oldsize > SIZE_MAX / sizeof(int64_t) - 1 ||
		(uint64_t)newsize > SIZE_MAX || stream == NULL || stream->malloc == NULL ||
		stream->free == NULL || stream->write == NULL || old == NULL || new == NULL) {
		return -1;
	}

	req.I = stream->malloc((oldsize + 1) * sizeof(int64_t));
	if (req.I == NULL) {
		return -1;
	}

	req.buffer = stream->malloc(PATCH_BUFFER_SIZE);
	if (req.buffer == NULL) {
		stream->free(req.I);
		return -1;
	}

	req.old = old;
	req.oldsize = oldsize;
	req.new = new;
	req.newsize = newsize;
	req.stream = stream;

	result = bsdiff_internal(req);

	stream->free(req.buffer);
	stream->free(req.I);

	return result;
}


struct output_streams
{
	FILE *file[3];
	uint8_t *buffer[3];
};

static int output_write(struct bsdiff_stream *stream, int channel, const void *data, int size)
{
	struct output_streams *outputs = stream->opaque;
	size_t count;

	count = fwrite(data, 1, (size_t)size, outputs->file[channel]);
	return count == (size_t)size ? 0 : -1;
}

int bsdiff_files(const char *oldpath, const char *newpath, const char *prefix)
{
	int inputs[2] = {-1, -1}, outputs[4] = {-1, -1, -1, -1};
	struct stat input_info[2], output_info[4];
	const char *input_paths[2] = {oldpath, newpath};
	char *paths[4] = {NULL, NULL, NULL, NULL};
	void *maps[2] = {NULL, NULL};
	static const uint8_t empty;
	const uint8_t *data[2] = {&empty, &empty};
	metadata_t metadata;
	fingerprint_t *fingerprints[5] = {&metadata.ctrl.fingerprint, &metadata.diff.fingerprint,
		&metadata.extra.fingerprint, &metadata.old_file.fingerprint,
		&metadata.new_file.fingerprint};
	struct output_streams output = {{NULL, NULL, NULL}, {NULL, NULL, NULL}};
	struct bsdiff_stream stream = {&output, malloc, free, output_write};
	uint8_t header[24];
	int i, result = -1, status;
	size_t count;

	metadata_init(&metadata);
	for (i = 0; i < 2; i++) {
		// Open an input image for hashing and read-only mapping.
		inputs[i] = open(input_paths[i], O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
		if (inputs[i] < 0) {
			goto cleanup;
		}
		status = regular_stat(inputs[i], &input_info[i]);
		if (status != 0 || (uintmax_t)input_info[i].st_size > SIZE_MAX) {
			goto cleanup;
		}
	}
	/* Reject impossible suffix-array allocations before touching any output. */
	if ((uintmax_t)input_info[0].st_size > SIZE_MAX / sizeof(int64_t) - 1 ||
		input_info[0].st_size > (INT64_MAX - 1) / 2 ||
		input_info[1].st_size > (INT64_MAX - 1) / 2) {
		goto cleanup;
	}
	for (i = 0; i < 4; i++) {
		paths[i] = path_join(prefix, suffixes[i]);
		if (paths[i] == NULL) {
			goto cleanup;
		}
		// Create or open this patch output without truncating it yet.
		outputs[i] = open(paths[i], O_RDWR | O_CREAT | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0666);
		if (outputs[i] < 0) {
			goto cleanup;
		}
		status = regular_stat(outputs[i], &output_info[i]);
		if (status != 0) {
			goto cleanup;
		}
	}
	for (i = 0; i < 2; i++) {
		if (input_info[i].st_size > 0) {
			// Map input bytes read-only for suffix sorting and difference generation.
			maps[i] =
				mmap(NULL, (size_t)input_info[i].st_size, PROT_READ, MAP_PRIVATE, inputs[i], 0);
			if (maps[i] == MAP_FAILED) {
				maps[i] = NULL;
				goto cleanup;
			}
			data[i] = maps[i];
		}
		status = hash_file(inputs[i], input_info[i].st_size, fingerprints[i + 3]);
		if (status != 0) {
			goto cleanup;
		}
	}
	for (i = 0; i < 4; i++) {
		// Clear the output before writing the new patch.
		status = ftruncate(outputs[i], 0);
		if (status != 0) {
			goto cleanup;
		}
	}
	for (i = 0; i < 3; i++) {
		output.file[i] = fdopen(outputs[i], "w+");
		if (output.file[i] == NULL) {
			goto cleanup;
		}
		outputs[i] = -1; /* Owned by FILE from now on. */
		output.buffer[i] = malloc(PATCH_BUFFER_SIZE);
		if (output.buffer[i] == NULL) {
			goto cleanup;
		}
		status = setvbuf(output.file[i], (char *)output.buffer[i], _IOFBF, PATCH_BUFFER_SIZE);
		if (status != 0) {
			goto cleanup;
		}
	}
	memcpy(header, PATCH_MAGIC, 16);
	status = patch_encode(input_info[1].st_size, header + 16);
	if (status != 0) {
		goto cleanup;
	}
	count = fwrite(header, 1, sizeof(header), output.file[0]);
	if (count != sizeof(header)) {
		goto cleanup;
	}
	status = bsdiff(data[0], input_info[0].st_size, data[1], input_info[1].st_size, &stream);
	if (status != 0) {
		goto cleanup;
	}
	for (i = 0; i < 3; i++) {
		status = fflush(output.file[i]);
		if (status != 0) {
			goto cleanup;
		}
		status = regular_stat(fileno(output.file[i]), &output_info[i]);
		if (status != 0) {
			goto cleanup;
		}
		status = hash_file(fileno(output.file[i]), output_info[i].st_size, fingerprints[i]);
		if (status != 0) {
			goto cleanup;
		}
	}
	result = metadata_write(outputs[3], &metadata);
cleanup:
	for (i = 0; i < 3; i++) {
		if (output.file[i] != NULL) {
			status = fclose(output.file[i]);
			if (status != 0) {
				result = -1;
			}
		}
		free(output.buffer[i]);
	}
	for (i = 0; i < 4; i++) {
		if (outputs[i] >= 0) {
			// Release an output descriptor not transferred to a FILE stream.
			status = close(outputs[i]);
			if (status != 0) {
				result = -1;
			}
		}
		free(paths[i]);
	}
	for (i = 0; i < 2; i++) {
		if (maps[i] != NULL) {
			// Release the input mapping during generator cleanup.
			munmap(maps[i], (size_t)input_info[i].st_size);
		}
		if (inputs[i] >= 0) {
			// Release the input descriptor during generator cleanup.
			close(inputs[i]);
		}
	}
	return result;
}
