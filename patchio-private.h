/* Internal file integration API; not part of the public stream interface. */
#ifndef PATCHIO_PRIVATE_H
#define PATCHIO_PRIVATE_H

#include "patchio.h"
#include <stddef.h>
#include <sys/stat.h>

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

extern const char *const suffixes[4];

void metadata_init(metadata_t *metadata);
int file_instance_close(file_instance_t *file);
void metadata_close(metadata_t *metadata);
char *path_join(const char *prefix, const char *suffix);
int read_at(int fd, void *buffer, size_t size, int64_t offset);
int read_exact(int fd, void *buffer, size_t size);
int write_exact(int fd, const void *buffer, size_t size);
int regular_stat(int fd, struct stat *info);
int hash_file(int fd, int64_t size, fingerprint_t *fingerprint);
int fingerprints_equal(const fingerprint_t *a, const fingerprint_t *b);
int metadata_write(int fd, const metadata_t *metadata);
int metadata_read(const char *prefix, metadata_t *metadata);

#endif
