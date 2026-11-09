/* Shared BSDIFF44 file integration. See LICENSE for redistribution terms. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "patchio-private.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *const suffixes[4] = {".ctrl", ".diff", ".extra", ".meta"};

void metadata_init(metadata_t *metadata)
{
	memset(metadata, 0, sizeof(*metadata));
	metadata->ctrl.fd = -1;
	metadata->diff.fd = -1;
	metadata->extra.fd = -1;
	metadata->old_file.fd = -1;
	metadata->new_file.fd = -1;
}

int file_instance_close(file_instance_t *file)
{
	int result = 0;

	if (file->fd >= 0) {
		// Release this owned descriptor.
		result = close(file->fd);
		file->fd = -1;
	}
	return result;
}

/* metadata_t owns these descriptors. Callbacks only borrow them. */
void metadata_close(metadata_t *metadata)
{
	file_instance_t *files[5] = {&metadata->ctrl, &metadata->diff, &metadata->extra,
		&metadata->old_file, &metadata->new_file};
	int i;

	for (i = 0; i < 5; i++) {
		file_instance_close(files[i]);
	}
}

int64_t patch_decode(const uint8_t bytes[8])
{
	uint64_t value = bytes[7] & 0x7f;
	int64_t result = 0;

	for (int i = 6; i >= 0; i--) {
		value = ((uint64_t)value * 256) + (uint64_t)bytes[i];
	}

	result = (int64_t)value;
	if ((bytes[7] & 0x80) != 0) {
		result = -result;
	}

	return result;
}

int patch_encode(int64_t value, uint8_t bytes[8])
{
	uint64_t magnitude;
	int i;

	if (value == INT64_MIN) {
		return -1;
	}
	magnitude = value < 0 ? (uint64_t)-value : (uint64_t)value;
	for (i = 0; i < 8; i++) {
		bytes[i] = (uint8_t)(magnitude & 255);
		magnitude >>= 8;
	}
	if (value < 0) {
		bytes[7] |= 0x80;
	}
	return 0;
}

int patch_add(int64_t left, int64_t right, int64_t *result)
{
	if ((right > 0 && left > INT64_MAX - right) || (right < 0 && left < INT64_MIN - right)) {
		return -1;
	}
	*result = left + right;
	return 0;
}

char *path_join(const char *prefix, const char *suffix)
{
	size_t a = strlen(prefix), b = strlen(suffix);
	char *path;

	if (a > SIZE_MAX - b - 1) {
		return NULL;
	}
	path = malloc(a + b + 1);
	if (path != NULL) {
		memcpy(path, prefix, a);
		memcpy(path + a, suffix, b + 1);
	}
	return path;
}

int read_at(int fd, void *buffer, size_t size, int64_t offset)
{
	uint8_t *data = buffer;
	ssize_t count;

	while (size > 0) {
		// Read bytes at the requested offset without moving the file position.
		count = pread(fd, data, size, (off_t)offset);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			return -1;
		}
		data += count;
		size -= (size_t)count;
		offset += count;
	}
	return 0;
}

int read_exact(int fd, void *buffer, size_t size)
{
	uint8_t *data = buffer;
	ssize_t count;

	while (size > 0) {
		// Read the next bytes from the current stream position.
		count = read(fd, data, size);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			return -1;
		}
		data += count;
		size -= (size_t)count;
	}
	return 0;
}

int write_exact(int fd, const void *buffer, size_t size)
{
	const uint8_t *data = buffer;
	ssize_t count;

	while (size > 0) {
		// Write the remaining bytes to the destination.
		count = write(fd, data, size);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			return -1;
		}
		data += count;
		size -= (size_t)count;
	}
	return 0;
}

int regular_stat(int fd, struct stat *info)
{
	int result;

	// Read the file type and length for regular-file validation.
	result = fstat(fd, info);
	if (result != 0 || !S_ISREG(info->st_mode) || info->st_size < 0 ||
		(uintmax_t)info->st_size > INT64_MAX) {
		return -1;
	}
	return 0;
}

int hash_file(int fd, int64_t size, fingerprint_t *fingerprint)
{
	EVP_MD_CTX *ctx = NULL;
	uint8_t *buffer = NULL;
	int64_t offset = 0;
	size_t chunk;
	unsigned int length = 0;
	int result = -1, status;

	ctx = EVP_MD_CTX_new();
	buffer = malloc(PATCH_BUFFER_SIZE);
	if (ctx == NULL || buffer == NULL || size < 0) {
		goto cleanup;
	}
	status = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if (status != 1) {
		goto cleanup;
	}
	while (offset < size) {
		chunk = size - offset < PATCH_BUFFER_SIZE ? (size_t)(size - offset) : PATCH_BUFFER_SIZE;
		status = read_at(fd, buffer, chunk, offset);
		if (status != 0) {
			goto cleanup;
		}
		status = EVP_DigestUpdate(ctx, buffer, chunk);
		if (status != 1) {
			goto cleanup;
		}
		offset += (int64_t)chunk;
	}
	status = EVP_DigestFinal_ex(ctx, fingerprint->hash, &length);
	if (status != 1 || length != 32) {
		goto cleanup;
	}
	fingerprint->size = size;
	result = 0;
cleanup:
	free(buffer);
	EVP_MD_CTX_free(ctx);
	return result;
}

int fingerprints_equal(const fingerprint_t *a, const fingerprint_t *b)
{
	int result;

	result = memcmp(a->hash, b->hash, 32);
	return a->size == b->size && result == 0;
}

/* .meta: 16-byte magic followed by five (8-byte size, 32-byte SHA-256)
 * records, in ctrl, diff, extra, old, new order. No padding or compression. */
int metadata_write(int fd, const metadata_t *metadata)
{
	uint8_t data[216];
	const fingerprint_t *fingerprints[5] = {&metadata->ctrl.fingerprint,
		&metadata->diff.fingerprint, &metadata->extra.fingerprint, &metadata->old_file.fingerprint,
		&metadata->new_file.fingerprint};
	int i, result;

	memcpy(data, PATCH_MAGIC, 16);
	for (i = 0; i < 5; i++) {
		result = patch_encode(fingerprints[i]->size, data + 16 + i * 40);
		if (result != 0) {
			return -1;
		}
		memcpy(data + 24 + i * 40, fingerprints[i]->hash, 32);
	}
	return write_exact(fd, data, sizeof(data));
}

/* Parse fingerprints into the caller; late validation failure keeps decoded
 * fields. Closing the metadata descriptor does not change the result. */
int metadata_read(const char *prefix, metadata_t *metadata)
{
	uint8_t data[216];
	struct stat info;
	char *path;
	int fd = -1, result = -1, status;

	/* Reading into an owner with live descriptors would discard ownership. */
	if (metadata->ctrl.fd >= 0 || metadata->diff.fd >= 0 || metadata->extra.fd >= 0 ||
		metadata->old_file.fd >= 0 || metadata->new_file.fd >= 0) {
		return -1;
	}

	// Create .meta file path.
	path = path_join(prefix, ".meta");
	if (path == NULL) {
		return -1;
	}

	// Open the metadata file for format validation.
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		goto cleanup;
	}
	// Check metadata file stability.
	status = regular_stat(fd, &info);
	if (status != 0 || info.st_size != sizeof(data)) {
		goto cleanup;
	}

	// Read data block
	status = read_exact(fd, data, sizeof(data));
	if (status != 0) {
		goto cleanup;
	}

	// Asses data block.
	status = memcmp(data, PATCH_MAGIC, 16);
	if (status != 0) {
		goto cleanup;
	}

	// Control file (.ctrl): total size including the header and SHA-256.
	metadata->ctrl.fingerprint.size = patch_decode(data + 16);
	memcpy(metadata->ctrl.fingerprint.hash, data + 24, 32);
	if (metadata->ctrl.fingerprint.size < 0) {
		goto cleanup;
	}

	// Difference payload file (.diff): total size and SHA-256.
	metadata->diff.fingerprint.size = patch_decode(data + 56);
	memcpy(metadata->diff.fingerprint.hash, data + 64, 32);
	if (metadata->diff.fingerprint.size < 0) {
		goto cleanup;
	}

	// Extra payload file (.extra): total size and SHA-256.
	metadata->extra.fingerprint.size = patch_decode(data + 96);
	memcpy(metadata->extra.fingerprint.hash, data + 104, 32);
	if (metadata->extra.fingerprint.size < 0) {
		goto cleanup;
	}

	// Old image file: logical data size and SHA-256.
	metadata->old_file.fingerprint.size = patch_decode(data + 136);
	memcpy(metadata->old_file.fingerprint.hash, data + 144, 32);
	if (metadata->old_file.fingerprint.size < 0) {
		goto cleanup;
	}

	// New image file: expected output size and SHA-256.
	metadata->new_file.fingerprint.size = patch_decode(data + 176);
	memcpy(metadata->new_file.fingerprint.hash, data + 184, 32);
	if (metadata->new_file.fingerprint.size < 0) {
		goto cleanup;
	}

	result = 0;

cleanup:
	if (fd >= 0) {
		// Close the metadata file before publishing the parsed values.
		(void) close(fd);
	}

	(void) free(path);

	return result;
}
