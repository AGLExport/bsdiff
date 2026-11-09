/* File integration for the BSDIFF44 format. See LICENSE for redistribution terms. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "bsdiff.h"
#include "bspatch.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

static const char *suffixes[4] = {".ctrl", ".diff", ".extra", ".meta"};

struct s_fingerprint
{
	int64_t size;
	uint8_t hash[32];
};
typedef struct s_fingerprint fingerprint_t;

struct s_file_instance
{
	fingerprint_t fingerprint;
	int fd;
};
typedef struct s_file_instance file_instance_t;

struct s_metadata
{
	file_instance_t ctrl;
	file_instance_t diff;
	file_instance_t extra;
	file_instance_t old_file;
	file_instance_t new_file;
};
typedef struct s_metadata metadata_t;

static void metadata_init(metadata_t *metadata)
{
	memset(metadata, 0, sizeof(*metadata));
	metadata->ctrl.fd = -1;
	metadata->diff.fd = -1;
	metadata->extra.fd = -1;
	metadata->old_file.fd = -1;
	metadata->new_file.fd = -1;
}

static int file_instance_close(file_instance_t *file)
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
static void metadata_close(metadata_t *metadata)
{
	file_instance_t *files[5] = {&metadata->ctrl, &metadata->diff, &metadata->extra,
		&metadata->old_file, &metadata->new_file};
	int i;

	for (i = 0; i < 5; i++) {
		file_instance_close(files[i]);
	}
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

static char *path_join(const char *prefix, const char *suffix)
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

static int read_at(int fd, void *buffer, size_t size, int64_t offset)
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

static int read_exact(int fd, void *buffer, size_t size)
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

static int write_exact(int fd, const void *buffer, size_t size)
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

static int regular_stat(int fd, struct stat *info)
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

static int hash_file(int fd, int64_t size, fingerprint_t *fingerprint)
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

static int fingerprints_equal(const fingerprint_t *a, const fingerprint_t *b)
{
	int result;

	result = memcmp(a->hash, b->hash, 32);
	return a->size == b->size && result == 0;
}

/* .meta: 16-byte magic followed by five (8-byte size, 32-byte SHA-256)
 * records, in ctrl, diff, extra, old, new order. No padding or compression. */
static int metadata_write(int fd, const metadata_t *metadata)
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

/* Publish metadata only after format validation and a successful close.
 * Payloads are checked by open_verified_patch_files()/validate_patch_data();
 * the old input is checked by open_verified_old_file(). */
static int metadata_read(const char *prefix, metadata_t *metadata)
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
