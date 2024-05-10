#define FUSE_USE_VERSION 26
#include "pixz.h"
#include <fuse.h>
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <assert.h>
#include <time.h>

#include <sys/prctl.h>
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

static void allow_debugger_attaching(void) {
    // enable gdb attach on Ubuntu (where /proc/sys/kernel/yama/ptrace_scope == 1)
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
}

static void time_diff(struct timespec *diff, const struct timespec *begin, const struct timespec *end) {
    diff->tv_sec = end->tv_sec - begin->tv_sec;
    diff->tv_nsec = end->tv_nsec - begin->tv_nsec;
    if (diff->tv_nsec < 0) { --diff->tv_sec; diff->tv_nsec += 1000000000; }
}

static struct timespec t_last_report;

int is_under_debugger(void);

static char *gSingleFileDestName;
static uint8_t __attribute((aligned(4096))) *gInputMMap;

static char *get_dest_name(const char *path) {
    const char *s = strrchr(path, '/');
    if (s) ++s; else s = path;
    size_t len = strlen(s);
    char *dest;
    if (strcasecmp(&s[len - 5], ".tpxz") == 0) {
        dest = malloc(len);
        memcpy(dest, s, len - 4);
        memcpy(&dest[len - 4], "tar", 4);
    } else if (strcasecmp(&s[len - 4], ".pxz") == 0) {
        dest = malloc(len - 3);
        memcpy(dest, s, len - 4);
        dest[len - 4] = '\0';
    } else {
        dest = xstrdup(s);
    }
    return dest;
}

#define MAXSPLITSIZE ((64 * 1024 * 1024) * 2)

typedef struct {
    size_t insize, outsize;
    off_t inoffset, outoffset;

    lzma_stream decompression_stream;
    lzma_block decompression_block;
    lzma_filter decompression_filters[LZMA_FILTERS_MAX + 1];

    lzma_check check;
} index_block_t;

static index_block_t *gIndexBlocks;
static unsigned gIndexBlocksSize;
static struct {
    unsigned read_ahead : 1;
    unsigned read_ahead_no_split_at_read_start_offsets : 1;
} options = {1, 1};

static void read_index_blocks(void) {
    lzma_index_iter iter;
    lzma_index_iter_init(&iter, gIndex);
    while (!lzma_index_iter_next(&iter, LZMA_INDEX_ITER_BLOCK)) {
        off_t boffset = iter.block.compressed_file_offset;
        fseeko(gInFile, boffset, SEEK_SET);

        if (iter.block.uncompressed_size > MAXSPLITSIZE) {
            die("Reading of big blocks is not implemented");
        } else {
            if ((gIndexBlocksSize & (gIndexBlocksSize - 1)) == 0) {
                gIndexBlocks = realloc(gIndexBlocks, (gIndexBlocksSize ? 2 * gIndexBlocksSize : 1) * sizeof *gIndexBlocks);
            }
            ++gIndexBlocksSize;

            index_block_t *ib = &gIndexBlocks[gIndexBlocksSize - 1];
            memset(ib, 0, sizeof *ib);
            ib->insize = iter.block.total_size;
            ib->outsize = iter.block.uncompressed_size;
            ib->inoffset = boffset;
            ib->outoffset = iter.block.uncompressed_file_offset;
            ib->check = iter.stream.flags->check;
        }
    }
    if (gIndexBlocksSize)
        gIndexBlocks = realloc(gIndexBlocks, gIndexBlocksSize * sizeof *gIndexBlocks);
}

static int pixz_single_file_fuse_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof *stbuf);
    if (path[0] == '/') {
        if (path[1] == '\0') {
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
            return 0;
        } else if (strcmp(&path[1], gSingleFileDestName) == 0) {
            stbuf->st_mode = S_IFREG | 0444;
            stbuf->st_nlink = 1;
            stbuf->st_size = gIndexBlocks[gIndexBlocksSize - 1].outoffset + gIndexBlocks[gIndexBlocksSize - 1].outsize;
            return 0;
        }
    }
    return -ENOENT;
}

static int pixz_single_file_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    if (strcmp(path, "/") == 0) {
        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);
        filler(buf, gSingleFileDestName, NULL, 0);
        return 0;
    }
    return -ENOENT;
}

static int pixz_single_file_fuse_open(const char *path, struct fuse_file_info *fi) {
    if (path[0] == '/') {
        if (strcmp(&path[1], gSingleFileDestName) == 0) {
            if ((fi->flags & O_ACCMODE) != O_RDONLY)
                return -EACCES;
            return 0;
        }
    }
    return -ENOENT;
}

static int index_block_find_outoffset(const void *A, const void *B) {
    const index_block_t *a = A, *b = B;
    if (a->outoffset < b->outoffset)
        return -1;
    if (a->outoffset == b->outoffset)
        return 0;
    // assume b is an element within gIndexBlocks array
    assert(gIndexBlocks <= b && b < gIndexBlocks + gIndexBlocksSize);
    if (b - gIndexBlocks == gIndexBlocksSize - 1)
        return 0;
    if ((b + 1)->outoffset <= a->outoffset)
        return 1;
    return 0;
}

struct decompressed_block_data {
    size_t size;
    unsigned char bytes[];
};

struct decompressed_block {
    size_t offset;
    struct decompressed_block_data *data;
};

struct tree;
static void decompressed_blocks_check(struct tree *tree);

#define TREE_NODE_KEY_VALUE_TYPE struct decompressed_block
#define TREE_NODE_KEY_TYPE size_t
#define TREE_NODE_KEY_VALUE_KEY(KV) ((KV).offset)
#define TREE_NODE_KEY_CMP(S_K, K) ((S_K) == (K) ? 0 : (S_K) > (K) ? 1 : -1)
#if 1
#define TREE_CHECK(tree) decompressed_blocks_check(tree)
#else
#define TREE_CHECK(tree) (void)0
#endif
#define TREE_NODE_FREE(node) free(node->key_value.data)
#include "tree.h"

struct tree decompressed_blocks;

struct decompressed_blocks_check_t {
    struct tree_node *prev_node;
};
static int decompressed_blocks_check_cb(void *data, struct tree_node *node) {
    struct decompressed_blocks_check_t *check_data = data;
    if (check_data->prev_node) {
        struct tree_traverse_context search_ctx; tree_traverse_context_init(&search_ctx);
        struct tree_node *found_node = tree_search(decompressed_blocks.root, node->key_value.offset, &search_ctx);
        assert(found_node == node);
        assert(check_data->prev_node == tree_previous(node, node->key_value.offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT));
        assert(node == tree_next(check_data->prev_node, check_data->prev_node->key_value.offset, &search_ctx, TREE_TRAVERSE_DO_NOT_UPDATE_CONTEXT));

        assert(check_data->prev_node->key_value.offset < node->key_value.offset);
        assert(check_data->prev_node->key_value.offset + check_data->prev_node->key_value.data->size <= node->key_value.offset);
    }
    check_data->prev_node = node;
    return 0;
}
static void decompressed_blocks_check(struct tree *tree) {
    struct decompressed_blocks_check_t data = {NULL};
    tree_iterate(tree, decompressed_blocks_check_cb, &data);
}

#ifndef DECOMPRESSED_CACHE_BLOCK_SIZE
#define DECOMPRESSED_CACHE_BLOCK_SIZE (4*1024*1024)
#endif

#ifndef MIN
#define MIN(a, b) ((b) > (a) ? (a) : (b))
#endif

static size_t cache_size;
static const size_t cache_max_size = (size_t)4 << 30;
static const size_t cache_clean_target_size = cache_max_size - cache_max_size / 4;

struct cache_cleanup_if_needed_t {
    size_t total_size;
};

static int cache_cleanup_if_needed_cb(void *data, struct tree_node *node) {
    struct cache_cleanup_if_needed_t *d = data;
    assert(d->total_size <= SIZE_MAX - node->key_value.data->size);
    d->total_size += node->key_value.data->size;
    return 0;
}

static void cache_cleanup_if_needed(size_t preserve_block_offset) {
    struct cache_cleanup_if_needed_t data = {0};
    int res = tree_iterate(&decompressed_blocks, cache_cleanup_if_needed_cb, &data); assert(res == 0);
    assert(cache_size == data.total_size);
    if (cache_size <= cache_max_size)
        return;
    printf("cache blocks: %lu, size: %lf MB, cleaning...\n", decompressed_blocks.length, cache_size / (1024 * 1024.0));
    struct tree_traverse_context search_ctx; tree_traverse_context_init(&search_ctx);
    struct tree_node *node = tree_search(decompressed_blocks.root, 0, &search_ctx);
    if (!node)
        node = tree_next(node, 0, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
    while (cache_size > cache_clean_target_size) {
        assert(node);
        struct tree_node *next_node = tree_next(node, node->key_value.offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
        if (node->key_value.offset != preserve_block_offset) {
            cache_size -= node->key_value.data->size;
            res = tree_delete(&decompressed_blocks, node->key_value.offset); assert(res);
        }
        node = next_node;
    }
    printf("  became blocks: %lu, size: %lf MB\n", decompressed_blocks.length, cache_size / (1024 * 1024.0)); fflush(stdout);
    clock_gettime(CLOCK_MONOTONIC, &t_last_report);
}

enum read_data_cached_copy_t {
    READ_DATA_CACHED_NO_COPY,
    READ_DATA_CACHED_COPY,
};

static size_t read_data_cached(char *buf, size_t size, size_t offset, enum read_data_cached_copy_t copy) {
    static const lzma_stream stream_reset = LZMA_STREAM_INIT;

    size_t len = gIndexBlocks[gIndexBlocksSize - 1].outoffset + gIndexBlocks[gIndexBlocksSize - 1].outsize;
    size_t preserve_block_offset = (size_t)-1;
    int were_some_additions = 0;
    if (offset < len) {
        if (size > len - offset)
            size = len - offset;

        size_t remaining_size = size;

        struct tree_traverse_context search_ctx; tree_traverse_context_init(&search_ctx);
        struct tree_node *cached_node = tree_search(decompressed_blocks.root, offset, &search_ctx);
        if (!cached_node) {
            cached_node = tree_previous(NULL, offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
            if (!cached_node || offset >= cached_node->key_value.offset + cached_node->key_value.data->size)
                cached_node = tree_next(cached_node, offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
        }
        struct decompressed_block_data *tmp_data = NULL;
        index_block_t *index_block = NULL;
        while (remaining_size) {
            if (cached_node && offset >= cached_node->key_value.offset) {
                size_t offset_diff = offset - cached_node->key_value.offset;
                assert(offset_diff < cached_node->key_value.data->size);
                size_t cached_size = MIN(remaining_size, cached_node->key_value.data->size - offset_diff);
                if (copy) {
                    memcpy(buf, cached_node->key_value.data->bytes + offset_diff, cached_size);
                    buf += cached_size;
                } else {
                    preserve_block_offset = cached_node->key_value.offset;
                    *(unsigned char**)buf = cached_node->key_value.data->bytes + offset_diff;
                    size = cached_size;
                    break;
                }
                offset += cached_size;
                assert(cached_size <= remaining_size);
                remaining_size -= cached_size;
                cached_node = tree_next(cached_node, offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
                continue;
            }
            if (!index_block) {
                index_block_t *reference = (void*)&offset - ((char*)&reference->outoffset - (char*)reference);
                index_block = bsearch(reference, gIndexBlocks, gIndexBlocksSize, sizeof *gIndexBlocks, index_block_find_outoffset);
                assert(index_block);
            }

            for (;; ++index_block) {
                assert(gIndexBlocks <= index_block && index_block < gIndexBlocks + gIndexBlocksSize);
                assert(index_block->outoffset <= offset);
                if (offset < index_block->outoffset + index_block->outsize)
                    break;
            }
            assert(index_block - gIndexBlocks == gIndexBlocksSize - 1 || (index_block + 1)->outoffset > offset);

            lzma_stream *stream = &index_block->decompression_stream;
            if (stream->next_in) {
                if (index_block->outoffset + stream->total_out > offset) {
                    lzma_end(stream);
                    memcpy(stream, &stream_reset, sizeof *stream);
                    memset(&index_block->decompression_block, 0, sizeof index_block->decompression_block);
                    memset(&index_block->decompression_filters, 0, sizeof index_block->decompression_filters);
                }
            }
            if (!stream->next_in) {
                uint8_t *input = gInputMMap + index_block->inoffset;
                lzma_block *block = &index_block->decompression_block;
                block->filters = index_block->decompression_filters;
                block->check = index_block->check;
                block->version = 0;
                block->header_size = lzma_block_header_size_decode(input[0]);
                if (lzma_block_header_decode(block, NULL, input) != LZMA_OK)
                    die("Error decoding block header");
                if (lzma_block_decoder(stream, block) != LZMA_OK)
                    die("Error initializing block decode");
                stream->avail_in = index_block->insize - block->header_size;
                stream->next_in = input + block->header_size;
                assert(stream->total_out == 0);
            }
            size_t decompression_offset = index_block->outoffset + stream->total_out;
            if (!cached_node || cached_node->key_value.offset != decompression_offset) {
                cached_node = tree_search(decompressed_blocks.root, decompression_offset, &search_ctx);
                if (!cached_node || cached_node->key_value.offset < decompression_offset) {
                    if (cached_node)
                        assert(cached_node->key_value.offset + cached_node->key_value.data->size <= decompression_offset);
                    cached_node = tree_next(cached_node, decompression_offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
                }
            }
            for (;;) {
                decompression_offset = index_block->outoffset + stream->total_out;
                struct decompressed_block_data *use_data;
                size_t block_size;
                if (cached_node && cached_node->key_value.offset == decompression_offset) {
                    block_size = cached_node->key_value.data->size;
                    if (tmp_data && tmp_data->size < block_size)
                        free(tmp_data), tmp_data = NULL;
                    if (!tmp_data) {
                        tmp_data = malloc(block_size + ((char*)&tmp_data->bytes - (char*)tmp_data));
                        tmp_data->size = block_size;
                    }
                    cached_node = tree_next(cached_node, decompression_offset, &search_ctx, TREE_TRAVERSE_UPDATE_CONTEXT);
                    use_data = tmp_data;
                } else {
                    if (decompression_offset < offset) {
                        block_size = offset - decompression_offset;
                        if (options.read_ahead_no_split_at_read_start_offsets)
                            block_size = DECOMPRESSED_CACHE_BLOCK_SIZE;
                    } else {
                        assert(decompression_offset == offset);
                        block_size = remaining_size;
                        if (options.read_ahead)
                            block_size = DECOMPRESSED_CACHE_BLOCK_SIZE;
                    }
                    if (cached_node) {
                        assert(cached_node->key_value.offset > decompression_offset);
                        if (block_size > cached_node->key_value.offset - decompression_offset)
                            block_size = cached_node->key_value.offset - decompression_offset;
                    }
                    if (stream->total_out + block_size > index_block->outsize)
                        block_size = index_block->outsize - stream->total_out;
                    if (block_size >= 2 * DECOMPRESSED_CACHE_BLOCK_SIZE)
                        block_size = DECOMPRESSED_CACHE_BLOCK_SIZE;
                    assert(block_size);
                    struct decompressed_block_data *block_data = malloc(block_size + ((char*)&block_data->bytes - (char*)block_data));
                    block_data->size = block_size;
                    struct decompressed_block out_block = {decompression_offset, block_data};
                    cache_size += block_size;
                    tree_insert(&decompressed_blocks, &out_block, &search_ctx);
                    were_some_additions = 1;
                    use_data = block_data;
                }
                stream->next_out = use_data->bytes;
                stream->avail_out = block_size;
                lzma_ret err = lzma_code(stream, LZMA_FINISH);
                if (err != LZMA_STREAM_END && err != LZMA_OK)
                    die("Error decoding block");
                assert(err == LZMA_OK || stream->avail_in == 0);
                assert(stream->avail_out == 0);
                assert(decompression_offset <= offset);
                size_t decompressed_size = stream->next_out - use_data->bytes;
                assert(decompressed_size);

                if (err == LZMA_STREAM_END) {
                    lzma_end(stream);
                    memcpy(stream, &stream_reset, sizeof *stream);
                    memset(&index_block->decompression_block, 0, sizeof index_block->decompression_block);
                    memset(&index_block->decompression_filters, 0, sizeof index_block->decompression_filters);
                }

                if (decompression_offset == offset || decompression_offset + block_size > offset) {
                    if (decompression_offset != offset) {
                        assert(decompression_offset + block_size > offset);
                        assert(options.read_ahead_no_split_at_read_start_offsets);
                    }
                    assert(offset >= decompression_offset);
                    size_t offset_diff = offset - decompression_offset;
                    assert(use_data != tmp_data);
                    assert(decompressed_size > offset_diff);
                    size_t copy_size = MIN(decompressed_size - offset_diff, remaining_size);
                    if (copy) {
                        memcpy(buf, use_data->bytes + offset_diff, copy_size);
                        buf += copy_size;
                    } else {
                        preserve_block_offset = decompression_offset;
                        *(unsigned char**)buf = use_data->bytes + offset_diff;
                        size = copy_size;
                        remaining_size = 0;
                        break;
                    }
                    offset += copy_size;
                    assert(copy_size <= remaining_size);
                    remaining_size -= copy_size;
                    if (remaining_size) {
                        if (err == LZMA_OK) {
                            if (offset_diff && !(cached_node && cached_node->key_value.offset == offset)) {
                                assert(options.read_ahead_no_split_at_read_start_offsets);
                                continue;
                            }
                            assert(cached_node && cached_node->key_value.offset == offset);
                        }
                    }
                    break;
                }
            }
        }
        free(tmp_data);
    } else {
        size = 0;
    }
    if (were_some_additions)
        cache_cleanup_if_needed(preserve_block_offset);
#if !TESTS
    static struct timespec t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_now);
    if (t_now.tv_sec - t_last_report.tv_sec > 60) {
        memcpy(&t_last_report, &t_now, sizeof t_last_report);
        fflush(stderr);
        printf("cache blocks: %lu, size: %lf MB\n", decompressed_blocks.length, cache_size / (1024 * 1024.0));
        fflush(stdout);
    }
#endif
    return size;
}

static int pixz_single_file_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    if (path[0] == '/') {
        if (strcmp(&path[1], gSingleFileDestName) == 0) {
            assert(size <= INT_MAX);
            assert(offset >= 0);
            return read_data_cached(buf, size, offset, READ_DATA_CACHED_COPY);
        }
    }
    return -ENOENT;
}

static struct fuse_operations pixz_single_file_fuse_operations = {
    .getattr = pixz_single_file_fuse_getattr,
    .readdir = pixz_single_file_fuse_readdir,
    .open    = pixz_single_file_fuse_open,
    .read    = pixz_single_file_fuse_read,
};


// multi-file tar archives

typedef unsigned long file_index_map_hash_t;
static unsigned gHashParam;

static file_index_map_hash_t compute_hash(const char *str, const char *end) {
    file_index_map_hash_t hash = 0;
    while (str != end && *str != '\0') {
        hash ^= (file_index_map_hash_t)(unsigned char)*str++;
        hash *= gHashParam;
    }
    return hash;
}

struct file_index_map_entry_t;

struct file_index_map_entry_children_t {
    size_t len;
    struct file_index_map_entry_t *data[];
};

struct file_index_map_entry_t {
    file_index_map_hash_t hash;
    const struct file_index_string_t *name;
    size_t in_archive_size; // uncompressed
    size_t in_archive_offset; // uncompressed
    size_t tar_data_start_offset; // uncompressed
    // from fcntl.h:
    //   #define S_IFMT    0170000 // These bits determine file type.
    //   #define S_IFDIR   0040000 // Directory.
    //   #define S_IFCHR   0020000 // Character device.
    //   #define S_IFBLK   0060000 // Block device.
    //   #define S_IFREG   0100000 // Regular file.
    //   #define S_IFIFO   0010000 // FIFO.
    //   #define S_IFLNK   0120000 // Symbolic link.
    //   #define S_IFSOCK  0140000 // Socket.
    mode_t mode;
    unsigned nlink;
    size_t size;
    uid_t uid;
    gid_t gid;
    struct timespec mtime;
    struct file_index_string_t *symlink;
    struct file_index_map_entry_children_t *children;
};

struct file_index_map_entry_t *gFileIndexMap;
size_t gFileIndexMapLength;

struct file_index_string_t {
    unsigned len;
    char data[];
};
static const unsigned file_index_string_t_alignment = _Alignof(struct file_index_string_t);


static struct file_index_string_t *gStringTable;
static size_t gStringTableSize;

static struct file_index_map_entry_children_t *gChildrenTable;

static int fill_file_index_map_cmp(const void *ap, const void *bp) {
    const struct file_index_map_entry_t *a = ap, *b = bp;
    if (a->hash < b->hash) return -1;
    if (a->hash > b->hash) return 1;
    return 0;
}

static int fill_file_index_map_hash_cmp(const void *ap, const void *bp) {
    const file_index_map_hash_t *a = ap, *b = bp;
    if (*a < *b) return -1;
    if (*a > *b) return 1;
    return 0;
}

static unsigned next_prime(unsigned last_prime) {
    static unsigned *primes, primes_length;
    unsigned new_prime;
    if (last_prime == 0) {
        free(primes); primes = NULL; primes_length = 0;
        return 1;
    }
    assert(last_prime < UINT_MAX - 1);
    for (new_prime = last_prime == 2 ? 3 : last_prime + 2; ; ++new_prime) {
        unsigned i;
        for (i = 0; i < primes_length; ++i) {
            if (new_prime % primes[i] == 0)
                break;
        }
        if (i == primes_length)
            break;
        assert(new_prime != UINT_MAX);
    }
    if ((primes_length & (primes_length - 1)) == 0) {
        primes = primes_length ? realloc(primes, 2 * primes_length * sizeof *primes) : malloc(sizeof *primes);
    }
    primes[primes_length++] = new_prime;
    return new_prime;
}

static int fill_file_index_map_cmp_by_offset(const void *ap, const void *bp) {
    const struct file_index_map_entry_t *const *app = ap, *const *bpp = bp, *a = *app, *b = *bpp;
    if (a->in_archive_offset < b->in_archive_offset) return -1;
    if (a->in_archive_offset > b->in_archive_offset) return 1;
    return 0;
}

static struct file_index_map_entry_t *file_index_map_lookup(file_index_map_hash_t hash) {
    struct file_index_map_entry_t *reference = (void*)&hash - ((char*)&reference->hash - (char*)reference);
    struct file_index_map_entry_t *found = bsearch(reference, gFileIndexMap, gFileIndexMapLength, sizeof *gFileIndexMap, fill_file_index_map_cmp);
    return found;
}

#define DEBUG_FILL_FILE_INDEX_MAP 1

static void fill_file_index_map(void) {
    static const char archive_root_entry_name[] = "";
    file_index_t *last = NULL;
    gFileIndexMapLength = 0;
    gStringTableSize = 0;
    for (file_index_t *f = gFileIndex; f != NULL; last = f, f = f->next) {
        ++gFileIndexMapLength;
        gStringTableSize += f->name ? ((char*)&gStringTable->data - (char*)gStringTable) + (strlen(f->name) + 1) + file_index_string_t_alignment - 1 : 0;
    }
    assert(last && last->name == NULL);
    // leave extra hash for archive root: "", don't do --gFileIndexMapLength;
    gStringTableSize += ((char*)&gStringTable->data - (char*)gStringTable) + file_index_string_t_alignment - 1; // archive root entry

    {
        file_index_map_hash_t *hashes = malloc(gFileIndexMapLength * sizeof *hashes);
        size_t min_collisions = SIZE_MAX;
        unsigned best_hash_param = 1;
        while ((gHashParam = next_prime(gHashParam)) <= 1000) {
            size_t hashes_length = 0;
            hashes[hashes_length++] = compute_hash(archive_root_entry_name, NULL); // archive root entry
            for (file_index_t *f = gFileIndex; f != last; f = f->next) {
                size_t name_len = strlen(f->name);
                const char *end = f->name[name_len - 1] == '/' ? &f->name[name_len - 1] : &f->name[name_len];
                hashes[hashes_length++] = compute_hash(f->name, end);
            }
            assert(hashes_length == gFileIndexMapLength);
            qsort(hashes, gFileIndexMapLength, sizeof *hashes, fill_file_index_map_hash_cmp);
            size_t collisions = 0;
            if (hashes_length) {
                file_index_map_hash_t prev = hashes[0];
                for (size_t i = 1; i < hashes_length; prev = hashes[i], ++i)
                    collisions += prev == hashes[i];
            }
            if (collisions < min_collisions) {
                min_collisions = collisions;
                best_hash_param = gHashParam;
            }
            if (collisions == 0)
                break;
        }
        next_prime(0);
        gHashParam = best_hash_param;
        assert(min_collisions == 0); // TODO: allow collisions
        free(hashes);
    }

    gFileIndexMap = malloc(gFileIndexMapLength * sizeof *gFileIndexMap);

    size_t map_idx = 0;
    memset(&gFileIndexMap[map_idx], 0, sizeof gFileIndexMap[map_idx]);
    gFileIndexMap[map_idx].hash = compute_hash(archive_root_entry_name, NULL); // archive root entry
    gFileIndexMap[map_idx].name = (const struct file_index_string_t *)archive_root_entry_name;
    gFileIndexMap[map_idx].in_archive_offset = (size_t)-1;
    gFileIndexMap[map_idx].mode = S_IFDIR;
    ++map_idx;
    for (file_index_t *f = gFileIndex; f != last; ++map_idx, f = f->next) {
        size_t name_len = strlen(f->name);
        const char *end = f->name[name_len - 1] == '/' ? &f->name[name_len - 1] : &f->name[name_len];
        memset(&gFileIndexMap[map_idx], 0, sizeof gFileIndexMap[map_idx]);
        gFileIndexMap[map_idx].hash = compute_hash(f->name, end);
        gFileIndexMap[map_idx].name = (const struct file_index_string_t *)f->name;
        assert(f->offset != (size_t)-1);
        gFileIndexMap[map_idx].in_archive_offset = f->offset;
        gFileIndexMap[map_idx].in_archive_size = f->next->offset - f->offset;
    }
    assert(map_idx == gFileIndexMapLength);
    qsort(gFileIndexMap, gFileIndexMapLength, sizeof *gFileIndexMap, fill_file_index_map_cmp);

    struct file_index_string_t *string_table_ptr = gStringTable = malloc(gStringTableSize);
    //size_t *index_map_entries_sorted_by_name = malloc(gFileIndexMapLength * sizeof *index_map_entries_sorted_by_name);
    for (map_idx = 0; map_idx < gFileIndexMapLength; ++map_idx) {
        //index_map_entries_sorted_by_name[map_idx] = map_idx;
        const char *name = (const char *)gFileIndexMap[map_idx].name;
        size_t str_len = strlen(name);
        if (str_len && name[str_len - 1] == '/') {
            assert(gFileIndexMap[map_idx].mode == 0);
            gFileIndexMap[map_idx].mode = S_IFDIR;
        }
        assert(name == archive_root_entry_name || str_len);
        assert(string_table_ptr < gStringTable + gStringTableSize);
        assert(str_len <= UINT_MAX);
        memcpy(string_table_ptr->data, name, str_len + 1);
        if (str_len && name[str_len - 1] == '/') {
            // don't store '/' at the end of directory names
            string_table_ptr->data[--str_len] = '\0';
            assert(str_len);
        }
        string_table_ptr->len = (unsigned)str_len;
        gFileIndexMap[map_idx].name = (struct file_index_string_t *)((char*)string_table_ptr - (char*)gStringTable);

        size_t new_string_table_ptr = (size_t)string_table_ptr;
        new_string_table_ptr += (char*)&gStringTable->data - (char*)gStringTable;
        new_string_table_ptr += str_len + 1;
        new_string_table_ptr = (new_string_table_ptr + file_index_string_t_alignment - 1) / file_index_string_t_alignment * file_index_string_t_alignment;
        string_table_ptr = (struct file_index_string_t *)new_string_table_ptr;
    }
    assert((char*)string_table_ptr <= (char*)gStringTable + gStringTableSize);

    gStringTableSize = (char*)string_table_ptr - (char*)gStringTable;
    gStringTable = realloc(gStringTable, gStringTableSize);
    for (map_idx = 0; map_idx < gFileIndexMapLength; ++map_idx) {
        gFileIndexMap[map_idx].name = (struct file_index_string_t *)((char*)gStringTable + (size_t)gFileIndexMap[map_idx].name);
        assert(gFileIndexMap[map_idx].name->len == strlen(gFileIndexMap[map_idx].name->data));
    }

#if DEBUG_FILL_FILE_INDEX_MAP
    for (map_idx = 0; map_idx < gFileIndexMapLength; ++map_idx) {
        printf("%lu: hash=0x%016lx in_archive_offset=%lu in_archive_size=%lu '%s'\n",
               map_idx,
               gFileIndexMap[map_idx].hash, gFileIndexMap[map_idx].in_archive_offset,
               gFileIndexMap[map_idx].in_archive_size, gFileIndexMap[map_idx].name->data);
    }
    printf("\n");
#endif

    size_t total_directories_with_children = 0;
    size_t total_children = 0;
    for (map_idx = 0; map_idx < gFileIndexMapLength; ++map_idx) {
        struct file_index_map_entry_t *file_entry = &gFileIndexMap[map_idx];
        const char *name = file_entry->name->data;
#if DEBUG_FILL_FILE_INDEX_MAP
        printf("%lu: name='%s'\n", map_idx, name);
#endif
        size_t nested_dir_slash_idx = 0;
        int is_upper_most_entry_but_not_root = 0;
        if (file_entry->name->len) {
            is_upper_most_entry_but_not_root = 1;
            for (size_t i = file_entry->name->len - 1; i != 0; --i) {
                if (name[i - 1] == '/') {
                    nested_dir_slash_idx = i;
                    while (--i != 0)
                        if (name[i - 1] == '/') {
                            is_upper_most_entry_but_not_root = 0;
                            break;
                        }
                    break;
                }
            }
        }
        if (nested_dir_slash_idx || is_upper_most_entry_but_not_root) {
            file_index_map_hash_t hash = compute_hash(name, name + (nested_dir_slash_idx ? nested_dir_slash_idx - 1 : 0));
#if DEBUG_FILL_FILE_INDEX_MAP
            printf("  parent -> hash=0x%016lx name='%.*s'\n", hash, (int)nested_dir_slash_idx, name);
#endif
            struct file_index_map_entry_t *parent = file_index_map_lookup(hash);
            assert(parent);
            assert(gFileIndexMap <= parent && parent < gFileIndexMap + gFileIndexMapLength);
            assert(parent->hash == hash);
            assert(parent->name->len == (nested_dir_slash_idx ? nested_dir_slash_idx - 1 : 0) && memcmp(parent->name->data, name, parent->name->len) == 0);
            assert(parent->mode == S_IFDIR);

            if (parent->children) {
                if ((parent->children->len & (parent->children->len - 1)) == 0)
                    parent->children = realloc(parent->children, 2 * parent->children->len * sizeof *parent->children->data + (char*)&parent->children->data - (char*)parent->children);
                ++parent->children->len;
            } else {
                ++total_directories_with_children;
                parent->children = malloc(1 * sizeof *parent->children->data + (char*)&parent->children->data - (char*)parent->children);
                parent->children->len = 1;
            }
            parent->children->data[parent->children->len - 1] = file_entry;
            ++total_children;
        }
    }
#if DEBUG_FILL_FILE_INDEX_MAP
    printf("\n");
#endif

    size_t children_table_size = 0;
    children_table_size += total_directories_with_children * ((char*)&gChildrenTable->data - (char*)gChildrenTable);
    children_table_size += total_children * sizeof *gChildrenTable->data;
    struct file_index_map_entry_children_t *children_ptr = gChildrenTable = malloc(children_table_size);
    for (map_idx = 0; map_idx < gFileIndexMapLength; ++map_idx) {
        struct file_index_map_entry_t *file_entry = &gFileIndexMap[map_idx];
        assert(file_entry->mode == 0 || file_entry->mode == S_IFDIR);
        assert(file_entry->mode == S_IFDIR || !file_entry->children);
        if (file_entry->mode != 0) {
#if DEBUG_FILL_FILE_INDEX_MAP
            printf("%lu: in_archive_offset=%lu name='%s' children=%lu\n", map_idx, file_entry->in_archive_offset, file_entry->name->data, file_entry->children ? file_entry->children->len : 0);
#endif
            if (file_entry->children) {
                assert(file_entry->children->len);
                size_t children_size = file_entry->children->len * sizeof *gChildrenTable->data + (char*)&gChildrenTable->data - (char*)gChildrenTable;
                memcpy(children_ptr, file_entry->children, children_size);
                free(file_entry->children);
                file_entry->children = children_ptr;
                children_ptr = (void*)children_ptr + children_size;
                qsort(file_entry->children->data, file_entry->children->len, sizeof *file_entry->children->data, fill_file_index_map_cmp_by_offset);
#if DEBUG_FILL_FILE_INDEX_MAP
                for (size_t i = 0; i < file_entry->children->len; ++i) {
                    printf("  %lu: in_archive_offset=%lu name='%s'\n", i, file_entry->children->data[i]->in_archive_offset, file_entry->children->data[i]->name->data);
                }
#endif
            }
        }
    }
    assert((char*)children_ptr == (char*)gChildrenTable + children_table_size);
#if DEBUG_FILL_FILE_INDEX_MAP
    printf("\n");
#endif
}

#define TAR_BLOCK_SIZE 512

struct pixz_archive_tar_read_context_t {
    struct file_index_map_entry_t *file_entry;
    size_t tar_offset;
};

static int pixz_archive_tar_ok(struct archive *ar, void *user_ptr) {
    return ARCHIVE_OK;
}

static ssize_t pixz_archive_tar_read(struct archive *ar, void *user_ptr, const void **bufp) {
    struct pixz_archive_tar_read_context_t *ctx = user_ptr;
    size_t buf_size = TAR_BLOCK_SIZE;
    assert(ctx->tar_offset < ctx->file_entry->in_archive_size);
    if (buf_size > ctx->file_entry->in_archive_size - ctx->tar_offset)
        buf_size = ctx->file_entry->in_archive_size - ctx->tar_offset;
    assert(ctx->tar_offset + buf_size <= ctx->file_entry->in_archive_size);
    size_t read_count = read_data_cached((char*)bufp, buf_size, ctx->file_entry->in_archive_offset + ctx->tar_offset, READ_DATA_CACHED_NO_COPY);
    assert(read_count); assert(read_count <= buf_size);
    ctx->tar_offset += read_count;
    return read_count;
}

static void load_file_entry_attributes(struct file_index_map_entry_t *file_entry) {
    if (file_entry->in_archive_offset != (size_t)-1) {
        struct archive_entry *entry;
        struct pixz_archive_tar_read_context_t context = {
            file_entry,
            0,
        };
        int is_dir = 0;
        struct archive *ar = archive_read_new();
        int tar_res = prevent_compression(ar); assert(tar_res == ARCHIVE_OK);
        tar_res = archive_read_support_format_tar(ar); assert(tar_res == ARCHIVE_OK);
        tar_res = archive_read_open(ar, &context, pixz_archive_tar_ok, pixz_archive_tar_read, pixz_archive_tar_ok); assert(tar_res == ARCHIVE_OK);
        tar_res = archive_read_next_header(ar, &entry); assert(tar_res == ARCHIVE_OK);
        file_entry->tar_data_start_offset = context.tar_offset;
        if ((file_entry->mode & S_IFMT) == S_IFDIR)
            is_dir = 1;
        file_entry->mode = archive_entry_mode(entry);
        assert(((file_entry->mode & S_IFMT) == S_IFDIR) == is_dir);
        nlink_t nl = archive_entry_nlink(entry);
        file_entry->nlink = nl <= UINT_MAX ? (unsigned)nl : UINT_MAX;
        if (!file_entry->nlink)
            file_entry->nlink = 1 + is_dir;
        file_entry->size = archive_entry_size(entry);
        file_entry->uid = archive_entry_uid(entry);
        file_entry->gid = archive_entry_gid(entry);

        if (archive_entry_mtime_is_set(entry)) {
            file_entry->mtime.tv_sec = archive_entry_mtime(entry);
            file_entry->mtime.tv_nsec = archive_entry_mtime_nsec(entry);
        }

        if ((file_entry->mode & S_IFMT) == S_IFLNK) {
            const char *symlink = archive_entry_symlink(entry);
            assert(symlink);
            size_t str_len = strlen(symlink);
            assert(str_len); assert(str_len <= UINT_MAX);
            file_entry->symlink = malloc((char*)&file_entry->symlink->data - (char*)file_entry->symlink + str_len + 1);
            file_entry->symlink->len = str_len;
            memcpy(file_entry->symlink->data, symlink, str_len + 1);
        }

        assert(memcmp(archive_entry_pathname(entry), file_entry->name->data, file_entry->name->len - is_dir) == 0);

        //archive_entry_clear(entry);
        finish_reading(ar);
    } else {
        assert(file_entry->name->len == 0 && file_entry->name->data[0] == '\0');
        file_entry->mode |= 0755;
        file_entry->nlink = 2;
        file_entry->size = 0;
        struct stat statbuf;
        if (fstat(fileno(gInFile), &statbuf) == 0) {
            file_entry->uid = statbuf.st_uid;
            file_entry->gid = statbuf.st_gid;
            file_entry->mtime = statbuf.st_mtim;
        }
    }
}

static int pixz_archive_fuse_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof *stbuf);
    if (path[0] == '/') {
        file_index_map_hash_t hash = compute_hash(&path[1], NULL);
        struct file_index_map_entry_t *file_entry = file_index_map_lookup(hash);
        if (file_entry && strcmp(file_entry->name->data, &path[1]) == 0) {
            if (!file_entry->nlink)
                load_file_entry_attributes(file_entry);
            stbuf->st_mode = file_entry->mode;
            stbuf->st_nlink = file_entry->nlink;
            stbuf->st_size = file_entry->size;
            stbuf->st_uid = file_entry->uid;
            stbuf->st_gid = file_entry->gid;
            stbuf->st_mtim = file_entry->mtime;
            return 0;
        }
    }
    return -ENOENT;
}

static const char *get_basename(const struct file_index_string_t *name) {
    for (size_t i = name->len - 1; i != 0; --i) {
        if (name->data[i - 1] == '/')
            return &name->data[i];
    }
    return name->data;
}

static int pixz_archive_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    if (path[0] == '/') {
        assert(offset == 0);
        file_index_map_hash_t hash = compute_hash(&path[1], NULL);
        struct file_index_map_entry_t *file_entry = file_index_map_lookup(hash);
        if (file_entry && strcmp(file_entry->name->data, &path[1]) == 0) {
            if ((file_entry->mode & S_IFMT) != S_IFDIR)
                return -ENOTDIR;
            filler(buf, ".", NULL, 0);
            filler(buf, "..", NULL, 0);
            if (file_entry->children)
                for (size_t i = 0; i < file_entry->children->len; ++i) {
                    int filler_result = filler(buf, get_basename(file_entry->children->data[i]->name), NULL, 0);
                    assert(filler_result == 0);
                }
            return 0;
        }
    }
    return -ENOENT;
}

static int pixz_archive_fuse_open(const char *path, struct fuse_file_info *fi) {
    if (path[0] == '/') {
        file_index_map_hash_t hash = compute_hash(&path[1], NULL);
        struct file_index_map_entry_t *file_entry = file_index_map_lookup(hash);
        if (file_entry && strcmp(file_entry->name->data, &path[1]) == 0) {
            if (!file_entry->nlink)
                load_file_entry_attributes(file_entry);
            if ((fi->flags & O_ACCMODE) != O_RDONLY)
                return -EACCES;
            return 0;
        }
    }
    return -ENOENT;
}

static int pixz_archive_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    file_index_map_hash_t hash = compute_hash(&path[1], NULL);
    struct file_index_map_entry_t *file_entry = file_index_map_lookup(hash);
    if (file_entry && strcmp(file_entry->name->data, &path[1]) == 0) {
        assert(file_entry->nlink); // attributes are ok
        if (offset < file_entry->size) {
            if (size > file_entry->size - offset)
                size = file_entry->size - offset;
            assert(size <= INT_MAX);
            assert(offset >= 0);

            assert(file_entry->tar_data_start_offset <= file_entry->in_archive_size);
            assert(offset + file_entry->tar_data_start_offset <= file_entry->in_archive_size);
            offset += file_entry->tar_data_start_offset;
            offset += file_entry->in_archive_offset;

            size = read_data_cached(buf, size, offset, READ_DATA_CACHED_COPY);
        } else {
            size = 0;
        }
        return size;
    }
    return -ENOENT;
}

static int pixz_archive_fuse_readlink(const char *path, char *buf, size_t size) {
    file_index_map_hash_t hash = compute_hash(&path[1], NULL);
    struct file_index_map_entry_t *file_entry = file_index_map_lookup(hash);
    if (file_entry && strcmp(file_entry->name->data, &path[1]) == 0) {
        assert(file_entry->nlink); // attributes are ok
        if ((file_entry->mode & S_IFMT) != S_IFLNK)
            return -EINVAL;
        assert(file_entry->symlink->len + 1 <= size);
        memcpy(buf, file_entry->symlink->data, file_entry->symlink->len + 1);
        return 0;
    }
    return -ENOENT;
}

static struct fuse_operations pixz_archive_fuse_operations = {
    .getattr  = pixz_archive_fuse_getattr,
    .readdir  = pixz_archive_fuse_readdir,
    .open     = pixz_archive_fuse_open,
    .read     = pixz_archive_fuse_read,
    .readlink = pixz_archive_fuse_readlink,
};

int pixz_mount_main(int argc, char **argv, bool tar) {
    char *ipath;

    clock_gettime(CLOCK_MONOTONIC, &t_last_report);

#if 1
    if (argc == 2 && strcmp(argv[1], "--test") == 0) {
        void pixz_tests(void);
        pixz_tests();
        return 0;
    }
#endif

    allow_debugger_attaching();

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
        return fuse_main(argc, argv, NULL, NULL);

    ipath = argv[1], argv[1] = argv[0], argv[0] = ipath;

    struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);
    if (fuse_opt_parse(&args, NULL, NULL, NULL) < 0)
        die("Can't parse options");
    fuse_opt_add_arg(&args, "-s");

    gInFile = fopen(ipath, "rb");
    if (!decode_index())
        die("No index in the archive provided");
    read_index_blocks();

    if (fseeko(gInFile, 0, SEEK_END) == -1) return 1;
    size_t in_file_len = ftello(gInFile);
    int in_file_fd = fileno(gInFile);
    for (void *hint = NULL;;) {
        gInputMMap = mmap(hint, in_file_len, PROT_READ, MAP_SHARED, in_file_fd, 0);
        if (gInputMMap == MAP_FAILED)
            die("Can't mmap: %d", errno);
        if (in_file_len >= 1 << 30 && ((size_t)gInputMMap & ((1 << 30) - 1))) {
            if (hint == NULL)
                hint = gInputMMap - ((size_t)gInputMMap & ((1 << 30) - 1));
            else
                hint += 1 << 30;
            if (munmap(gInputMMap, in_file_len))
                die("Can't unmap");
            continue;
        }
        break;
    }

    int ret;
    if (tar) {
        read_file_index();
        fill_file_index_map();
        free_file_index();
        ret = fuse_main(args.argc, args.argv, &pixz_archive_fuse_operations, NULL);
    } else {
        gSingleFileDestName = get_dest_name(ipath);
        ret = fuse_main(args.argc, args.argv, &pixz_single_file_fuse_operations, NULL);
    }
    fuse_opt_free_args(&args);
    return ret;
}
