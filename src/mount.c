#define FUSE_USE_VERSION 26
#include "pixz.h"
#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <assert.h>
#include <time.h>

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
    unsigned read_ahead_no_split_by_read_start_offsets : 1;
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
    if (b[1].outoffset <= a->outoffset)
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

static void cache_cleanup_if_needed(void) {
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
        cache_size -= node->key_value.data->size;
        res = tree_delete(&decompressed_blocks, node->key_value.offset); assert(res);
        node = next_node;
    }
    printf("  became blocks: %lu, size: %lf MB\n", decompressed_blocks.length, cache_size / (1024 * 1024.0)); fflush(stdout);
    clock_gettime(CLOCK_MONOTONIC, &t_last_report);
}

static int pixz_single_file_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    static const lzma_stream stream_reset = LZMA_STREAM_INIT;
    if (path[0] == '/') {
        if (strcmp(&path[1], gSingleFileDestName) == 0) {
            size_t len = gIndexBlocks[gIndexBlocksSize - 1].outoffset + gIndexBlocks[gIndexBlocksSize - 1].outsize;
            int were_some_additions = 0;
            if (offset < len) {
                assert(size <= INT_MAX);
                if (offset + size > len)
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
                        memcpy(buf, cached_node->key_value.data->bytes + offset_diff, cached_size);
                        offset += cached_size;
                        buf += cached_size;
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
                    assert(index_block - gIndexBlocks == gIndexBlocksSize - 1 || index_block[1].outoffset > offset);

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
                                if (options.read_ahead_no_split_by_read_start_offsets)
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
                            //struct tree_node *next_node = tree_search(cached_node, decompression_offset, &search_ctx); assert(next_node == NULL);
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
                                assert(options.read_ahead_no_split_by_read_start_offsets);
                            }
                            assert(offset >= decompression_offset);
                            size_t offset_diff = offset - decompression_offset;
                            assert(use_data != tmp_data);
                            assert(decompressed_size > offset_diff);
                            size_t copy_size = MIN(decompressed_size - offset_diff, remaining_size);
                            memcpy(buf, use_data->bytes + offset_diff, copy_size);
                            offset += copy_size;
                            buf += copy_size;
                            assert(copy_size <= remaining_size);
                            remaining_size -= copy_size;
                            if (remaining_size) {
                                if (err == LZMA_OK) {
                                    if (offset_diff && !(cached_node && cached_node->key_value.offset == offset)) {
                                        assert(options.read_ahead_no_split_by_read_start_offsets);
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
                cache_cleanup_if_needed();
#if !TESTS
            static struct timespec t_now;
            clock_gettime(CLOCK_MONOTONIC, &t_now);
            if (t_now.tv_sec - t_last_report.tv_sec > 60) {
                memcpy(&t_last_report, &t_now, sizeof t_last_report);
                fflush(stderr); printf("cache blocks: %lu\n", decompressed_blocks.length); fflush(stdout);
            }
#endif
            return size;
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
        gInputMMap = mmap(hint, in_file_len, PROT_READ, MAP_PRIVATE, in_file_fd, 0);
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
    tar = 0;
    if (tar) {
        //assert(0);
        ret = 1;
    } else {
        gSingleFileDestName = get_dest_name(ipath);
        //read_start();
        //if (pixz_single_file_fuse_read("/test.tar", argv[0], 20, 10, NULL))
        //    return 0;
        ret = fuse_main(args.argc, args.argv, &pixz_single_file_fuse_operations, NULL);
    }
    fuse_opt_free_args(&args);
    return ret;
    //return fuse_main(argc - 1, argv + 1, &pixz_fuse_operations, (void*)123);
}
