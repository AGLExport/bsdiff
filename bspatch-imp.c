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
#include <linux/fs.h>
#include <openssl/evp.h>
#include <sys/ioctl.h>

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


static const file_instance_t *patch_file(const metadata_t *metadata, int channel)
{
	switch (channel) {
	case PATCH_CTRL:
		return &metadata->ctrl;
	case PATCH_DIFF:
		return &metadata->diff;
	case PATCH_EXTRA:
		return &metadata->extra;
	default:
		return NULL;
	}
}

/* Open directly into metadata and verify each component.
 * On failure, close this call's descriptors and reset them to -1. */
static int open_verified_patch_files(const char *prefix, metadata_t *metadata)
{
	file_instance_t *files[3] = {&metadata->ctrl, &metadata->diff, &metadata->extra};
	fingerprint_t actual;
	struct stat info;
	char *path = NULL;
	int i, status;

	if ((files[0]->fd >= 0) || (files[1]->fd >= 0) || (files[2]->fd >= 0))
	{
		return -1;
	}

	// Open .ctrl, .diff, .extra files.
	for (i = 0; i < 3; i++) {
		path = path_join(prefix, suffixes[i]);
		if (path == NULL) {
			goto failure;
		}
		// Open this patch component read-only for verification and application.
		files[i]->fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
		free(path);
		path = NULL;
		if (files[i]->fd < 0) {
			goto failure;
		}
	}

	//Asses to .ctrl, .diff, .extra data.
	for (i = 0; i < 3; i++) {
		status = regular_stat(files[i]->fd, &info);
		if (status != 0 || info.st_size != files[i]->fingerprint.size) {
			goto failure;
		}
		status = hash_file(files[i]->fd, info.st_size, &actual);
		if (status != 0) {
			goto failure;
		}
		status = fingerprints_equal(&actual, &files[i]->fingerprint);
		if (status == 0) {
			goto failure;
		}
	}

	return 0;

failure:
	free(path);
	for (i = 0; i < 3; i++) {
		if (files[i]->fd >= 0) {
			// Release a partially opened component.
			file_instance_close(files[i]);
		}
	}

	return -1;
}

/* Only the metadata-declared prefix of a block device is old image data.
 * Publish its fd and stat information together after all checks succeed. */
static int open_verified_old_file(const char *path, file_instance_t *old, struct stat *info)
{
	const fingerprint_t *expected = &old->fingerprint;
	struct stat opened_info;
	fingerprint_t actual;
	int fd, status;

	if (old->fd >= 0 || expected->size < 0) {
		return -1;
	}
	// Open the old image or device for verification and later reads.
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		return -1;
	}
	// Determine whether the old source is a regular file or block device.
	status = fstat(fd, &opened_info);
	if (status != 0) {
		goto failure;
	}
	if (S_ISREG(opened_info.st_mode)) {
		if (opened_info.st_size < 0 || (uintmax_t)opened_info.st_size != (uint64_t)expected->size) {
			goto failure;
		}
	} else if (S_ISBLK(opened_info.st_mode)) {
		uint64_t capacity;

		// Check that the device can hold the metadata-declared old image.
		status = ioctl(fd, BLKGETSIZE64, &capacity);
		if (status != 0 || capacity < (uint64_t)expected->size) {
			goto failure;
		}
	} else {
		goto failure;
	}
	status = hash_file(fd, expected->size, &actual);
	if (status != 0) {
		goto failure;
	}
	status = fingerprints_equal(&actual, expected);
	if (status == 0) {
		goto failure;
	}
	old->fd = fd;
	*info = opened_info;
	return 0;
failure:
	// Release the old source after validation fails.
	close(fd);
	return -1;
}

struct input_streams
{
	metadata_t *metadata;
	EVP_MD_CTX *digest;
};

static int input_read(struct bspatch_stream *stream, int channel, void *data, int size)
{
	struct input_streams *inputs = stream->opaque;
	const file_instance_t *file = patch_file(inputs->metadata, channel);

	if (file == NULL) {
		return -1;
	}
	return read_exact(file->fd, data, (size_t)size);
}

static int old_read(struct bspatch_stream *stream, int64_t offset, void *data, int size)
{
	struct input_streams *inputs = stream->opaque;

	return read_at(inputs->metadata->old_file.fd, data, (size_t)size, offset);
}

static int new_write(struct bspatch_stream *stream, const void *data, int size)
{
	struct input_streams *inputs = stream->opaque;

	return write_exact(inputs->metadata->new_file.fd, data, (size_t)size);
}

static int digest_write(struct bspatch_stream *stream, const void *data, int size)
{
	struct input_streams *inputs = stream->opaque;
	int result;

	result = EVP_DigestUpdate(inputs->digest, data, (size_t)size);
	return result == 1 ? 0 : -1;
}

static int verify_device_target(
	struct bspatch_stream *stream, int64_t oldsize, int64_t newsize, const fingerprint_t *expected)
{
	struct input_streams *inputs = stream->opaque;
	struct bspatch_stream verifier = *stream;
	fingerprint_t actual;
	unsigned int length;
	int result = -1, status;

	inputs->digest = EVP_MD_CTX_new();
	if (inputs->digest == NULL) {
		return -1;
	}
	status = EVP_DigestInit_ex(inputs->digest, EVP_sha256(), NULL);
	if (status != 1) {
		goto cleanup;
	}
	verifier.write = digest_write;
	status = bspatch(oldsize, newsize, &verifier);
	if (status != 0) {
		goto cleanup;
	}
	status = EVP_DigestFinal_ex(inputs->digest, actual.hash, &length);
	if (status != 1 || length != 32) {
		goto cleanup;
	}
	actual.size = newsize;
	status = fingerprints_equal(&actual, expected);
	if (status == 0) {
		goto cleanup;
	}
	result = 0;
cleanup:
	EVP_MD_CTX_free(inputs->digest);
	inputs->digest = NULL;
	return result;
}

/* Check every control record and exact payload sizes before opening a device. */
static int validate_controls(int fd, const int64_t sizes[3], int64_t newsize)
{
	uint8_t record[24];
	int64_t offset = 24, newpos = 0, oldpos = 0, diff = 0, extra = 0, ctrl[3], end;
	int i, result;

	if (sizes[0] < 24 || (sizes[0] - 24) % 24 != 0) {
		return -1;
	}
	while (offset < sizes[0]) {
		if (newpos == newsize) {
			return -1;
		}
		result = read_at(fd, record, sizeof(record), offset);
		if (result != 0) {
			return -1;
		}
		for (i = 0; i < 3; i++) {
			ctrl[i] = patch_decode(record + i * 8);
		}
		if (ctrl[0] < 0 || ctrl[1] < 0 || ctrl[0] > newsize - newpos ||
			ctrl[1] > newsize - newpos - ctrl[0] || ctrl[0] > sizes[1] - diff ||
			ctrl[1] > sizes[2] - extra) {
			return -1;
		}
		result = patch_add(oldpos, ctrl[0], &end);
		if (result != 0) {
			return -1;
		}
		result = patch_add(end, ctrl[2], &oldpos);
		if (result != 0) {
			return -1;
		}
		newpos += ctrl[0] + ctrl[1];
		diff += ctrl[0];
		extra += ctrl[1];
		offset += 24;
	}
	return newpos == newsize && diff == sizes[1] && extra == sizes[2] ? 0 : -1;
}

/* Rewind payloads, skipping the unchanged control header on every pass. */
static int rewind_patch_files(const metadata_t *metadata)
{
	int i;
	off_t result;

	for (i = 0; i < 3; i++) {
		off_t offset = i == PATCH_CTRL ? 24 : 0;

		// Position the stream at its payload, skipping the control header if needed.
		result = lseek(patch_file(metadata, i)->fd, offset, SEEK_SET);
		if (result != offset) {
			return -1;
		}
	}
	return 0;
}

/* Validate headers and records using the already verified sources.
 * No file is modified. Successful validation positions each payload for use. */
static int validate_patch_data(const metadata_t *metadata, int64_t *newsize)
{
	uint8_t header[24];
	int64_t sizes[3] = {metadata->ctrl.fingerprint.size, metadata->diff.fingerprint.size,
		metadata->extra.fingerprint.size};
	int64_t target_size;
	int status;

	if (sizes[0] < 24) {
		return -1;
	}
	status = read_at(metadata->ctrl.fd, header, sizeof(header), 0);
	if (status != 0) {
		return -1;
	}
	status = memcmp(header, PATCH_MAGIC, 16);
	target_size = patch_decode(header + 16);
	if (status != 0 || target_size < 0 || target_size != metadata->new_file.fingerprint.size) {
		return -1;
	}
	status = validate_controls(metadata->ctrl.fd, sizes, target_size);
	if (status != 0) {
		return -1;
	}
	status = rewind_patch_files(metadata);
	if (status != 0) {
		return -1;
	}
	*newsize = target_size;
	return 0;
}

int bspatch_files(
	const char *oldpath, const char *newpath, const char *prefix, const char *unpackdir)
{
	metadata_t metadata;
	struct input_streams inputs = {&metadata, NULL};
	struct bspatch_stream stream = {&inputs, input_read, old_read, new_write};
	fingerprint_t actual;
	struct stat info, destination, old_info;
	char *temporary = NULL;
	int64_t newsize;
	int result = -1, status, block = 0, have_temporary = 0;

	metadata_init(&metadata);
	/* Retain the existing argument without creating staging files. */
	// Confirm the compatibility directory argument names an existing directory.
	status = stat(unpackdir, &info);
	if (status != 0 || !S_ISDIR(info.st_mode)) {
		goto cleanup;
	}
	status = metadata_read(prefix, &metadata);
	if (status != 0) {
		goto cleanup;
	}
	status = open_verified_patch_files(prefix, &metadata);
	if (status != 0) {
		goto cleanup;
	}
	status = open_verified_old_file(oldpath, &metadata.old_file, &old_info);
	if (status != 0) {
		goto cleanup;
	}
	status = validate_patch_data(&metadata, &newsize);
	if (status != 0) {
		goto cleanup;
	}
	// Inspect the destination without following a symbolic link.
	status = lstat(newpath, &destination);
	if (status == 0) {
		block = S_ISBLK(destination.st_mode);
		if (!block && !S_ISREG(destination.st_mode)) {
			goto cleanup;
		}
	} else if (errno != ENOENT) {
		goto cleanup;
	}
	if (block) {
		/* Direct in-place device writes could overwrite future old reads. */
		if (S_ISBLK(old_info.st_mode) && old_info.st_rdev == destination.st_rdev) {
			goto cleanup;
		}
		/* Verify the reconstructed digest before the first direct device write. */
		status = verify_device_target(
			&stream, metadata.old_file.fingerprint.size, newsize, &metadata.new_file.fingerprint);
		if (status != 0) {
			goto cleanup;
		}
		status = rewind_patch_files(&metadata);
		if (status != 0) {
			goto cleanup;
		}
		/* Explicit block destinations are written directly after validation. */
		// Open the destination device for direct writes and read-back hashing.
		metadata.new_file.fd = open(newpath, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
		if (metadata.new_file.fd < 0) {
			goto cleanup;
		}
		// Verify the opened descriptor still identifies the intended block device.
		status = fstat(metadata.new_file.fd, &info);
		if (status != 0 || !S_ISBLK(info.st_mode) || info.st_rdev != destination.st_rdev ||
			(S_ISBLK(old_info.st_mode) && info.st_rdev == old_info.st_rdev)) {
			goto cleanup;
		}
		{
			uint64_t capacity;

			// Ensure the destination device has capacity for the complete new image.
			status = ioctl(metadata.new_file.fd, BLKGETSIZE64, &capacity);
			if (status != 0 || (uint64_t)newsize > capacity) {
				goto cleanup;
			}
		}
	} else {
		temporary = path_join(newpath, ".tmp.XXXXXX");
		if (temporary == NULL) {
			goto cleanup;
		}
		// Create a unique sibling output file to preserve the destination on failure.
		metadata.new_file.fd = mkostemp(temporary, O_CLOEXEC | O_NOFOLLOW);
		if (metadata.new_file.fd < 0) {
			goto cleanup;
		}
		have_temporary = 1;
		// Apply the old source's access permissions to the temporary output.
		status = fchmod(metadata.new_file.fd, old_info.st_mode & 0777);
		if (status != 0) {
			goto cleanup;
		}
	}
	status = bspatch(metadata.old_file.fingerprint.size, newsize, &stream);
	if (status != 0) {
		goto cleanup;
	}
	status = hash_file(metadata.new_file.fd, newsize, &actual);
	if (status != 0) {
		goto cleanup;
	}
	status = fingerprints_equal(&actual, &metadata.new_file.fingerprint);
	if (status == 0) {
		goto cleanup;
	}
	// Flush completed output before closing it and publishing a regular file.
	status = fsync(metadata.new_file.fd);
	if (status != 0) {
		goto cleanup;
	}
	status = file_instance_close(&metadata.new_file);
	if (status != 0) {
		goto cleanup;
	}
	if (!block) {
		// Atomically replace the destination with the verified temporary output.
		status = rename(temporary, newpath);
		if (status != 0) {
			goto cleanup;
		}
		free(temporary);
		temporary = NULL;
		have_temporary = 0;
	}
	result = 0;

cleanup:
	metadata_close(&metadata);
	if (have_temporary) {
		// Remove the unfinished temporary output after an error.
		unlink(temporary);
	}
	free(temporary);
	return result;
}
