# bsdiff / bspatch

Binary difference generation and streaming patch application, based on Colin
Percival's algorithm and Matthew Endsley's embeddable implementation. This tree
implements the requirements in `../REQUIREMENT.md`.

## Build and run

Linux, a C99 compiler, and OpenSSL development headers/libcrypto are required. The
current format is uncompressed and does not use bzip2.

```sh
sh autogen.sh
./configure
make
./bsdiff old.bin new.bin update
mkdir -p patch-work
./bspatch old.bin restored.bin update patch-work
cmp new.bin restored.bin
```

For direct CLI builds:

```sh
cc -O2 -std=c99 -DBSDIFF_EXECUTABLE bsdiff.c bsdiff-imp.c patchio.c -lcrypto -o bsdiff
cc -O2 -std=c99 -DBSPATCH_EXECUTABLE bspatch.c bspatch-imp.c patchio.c -lcrypto -o bspatch
```

For a library, compile `bsdiff-imp.c`, `bspatch-imp.c`, and `patchio.c` without
CLI macros. Public function names and stream interfaces are unchanged.

## Source organization

- `bsdiff.c` / `bspatch.c`: CLI argument checks and calls to the file APIs.
- `bsdiff-imp.c`: difference algorithm, mapped inputs, buffered patch outputs,
  and `bsdiff_files()`.
- `bspatch-imp.c`: streaming application algorithm, verified source opens,
  control validation, device verification, output replacement, and `bspatch_files()`.
- `patchio.c`: integer encoding, shared I/O, SHA-256, metadata serialization,
  and descriptor initialization/cleanup.
- `patchio-private.h`: internal metadata types and shared implementation declarations;
  applications use `bsdiff.h`, `bspatch.h`, and `patchio.h`.

## BSDIFF44 files

The generator accepts a prefix and writes files with these suffixes:

| Suffix | Contents |
| --- | --- |
| `.ctrl` | 16-byte `ENDSLEY/BSDIFF44`, 8-byte new size, then 24-byte control records |
| `.diff` | Raw difference bytes, concatenated in record order |
| `.extra` | Raw extra bytes, concatenated in record order |
| `.meta` | Sizes and SHA-256 digests of the three components and both inputs |

The generator does not compare file identities between inputs, outputs, or
the existing prefix path.

The later noncompression requirement takes precedence over earlier bzip2
references in the requirements document. There are no compressed streams or
bzip2 CRCs. Empty payload files have zero bytes. BSDIFF43 is unsupported.

Integers use eight-byte little-endian sign-magnitude encoding; the most
significant bit is the sign, negative zero decodes to zero, and `INT64_MIN`
cannot be encoded. A control record contains diff length, extra length, and
signed adjustment of the old position after the diff segment.

`.meta` is exactly 216 bytes: the same 16-byte magic followed by five 40-byte
records in `.ctrl`, `.diff`, `.extra`, old, new order. Each record contains an
eight-byte nonnegative size and a 32-byte binary SHA-256 digest. The `.ctrl`
fingerprint includes its header. No native C struct layout is serialized.

## Library and resource behavior

`bsdiff_files(oldpath, newpath, prefix)` and
`bspatch_files(oldpath, newpath, prefix, unpackdir)` return zero on success and
-1 on failure. `main` only validates arguments and calls these functions.

`bsdiff()` accepts memory inputs and a `bsdiff_stream` allocator plus a write
callback with a `PATCH_CTRL`, `PATCH_DIFF`, or `PATCH_EXTRA` channel.
`bspatch(oldsize, newsize, stream)` uses channel reads, bounded old-file reads,
and sequential output writes. All callbacks return zero for complete success;
any nonzero result fails. See the public headers for signatures. The old
interleaved stream API is intentionally replaced.

Internal `metadata_t` holds five `file_instance_t` members, each containing
`fingerprint` (size and SHA-256) and `fd`. Parsed descriptors start at -1;
patch opens store descriptors directly and reset them to -1 on verification
failure. Old-image opens store their descriptor after verification. Callbacks borrow metadata and
`metadata_close()` closes every owned descriptor once and resets it to -1.
Runtime descriptors and C struct padding are never serialized; `.meta` remains
216 bytes.

Every file open uses `O_CLOEXEC | O_NOFOLLOW`. The final path component must
not be a symbolic link; directory components use normal path resolution.
Temporary output uses `mkostemp` with the same flags, and `fdopen` reuses an
already-open descriptor. Application uses `lstat` to reject both existing and
dangling symbolic links at its output path.

Generation maps regular input files read-only with `MAP_PRIVATE`, handles empty
inputs without mmap, and uses a 512 KiB diff buffer. Each output stream has a
512 KiB stdio buffer. The suffix arrays still require two arrays of
`(oldsize + 1) * sizeof(int64_t)` during sorting. No blanket sequential advice
or page eviction is applied to these random-access mappings.

Application opens the three raw components read-only and verifies their sizes
and SHA-256 before application. Generation and application do not use file
locks. Patch and old-image data must remain unchanged throughout verification
and application.

Application reads directly from the same verified descriptors without
reopening or copying the patch files. The control header remains unchanged;
control reads start at offset 24, while diff and extra reads start at offset 0.
The existing `unpackdir` argument is retained and checked as a directory for
compatibility, but no staging files or directories are created there.

Old data is fetched with `pread`. The old source may be a regular file or a block device containing the old image at offset zero. Regular
files must exactly match the metadata size; block capacity may be larger,
but only the declared old-image length is hashed and used for old reads.
Direct output to the same source block device is rejected. Transfer buffers
are at most 512 KiB, including for intervals larger than `INT_MAX`. Source files
must remain unchanged throughout processing. No mmap or madvise is used by
application.

Regular output uses a sibling temporary file and replaces the destination only
after output SHA-256 verification and successful I/O. In-place application is
supported for regular files. Explicit block-device destinations verify the
reconstructed digest before writing directly; hardware write failures cannot
be rolled back. Normal exits remove temporary output files; forced termination
may leave them behind.

## Validation

Run `python3 tests/compare.py` and
`python3 -m unittest discover -s tests -v` from the parent directory. See
`../tests/README.md` for baseline capture, large intervals, sanitizer checks,
and benchmarks.

## Credits and license

Copyright 2003–2005 Colin Percival; copyright 2012 Matthew Endsley.
Redistribution follows the BSD 2-clause license in `LICENSE`.
The original algorithm is described in
[Naïve Differences of Executable Code](https://www.daemonology.net/papers/bsdiff.pdf).
