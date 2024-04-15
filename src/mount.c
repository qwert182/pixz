#define FUSE_USE_VERSION 26
#include "pixz.h"
#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <assert.h>

static char *gSingleFileDestName;
static uint8_t *gInputMap;

static char *get_dest_name(const char *path) {
    const char *s = strrchr(path, '/');
    if (s) ++s; else s = path;
    size_t len = strlen(s);
    char *dest;
    if (strcasecmp(&s[len-5], ".tpxz") == 0) {
        dest = malloc(len);
        memcpy(dest, s, len - 4);
        memcpy(&dest[len-4], "tar", 4);
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
/*
typedef enum { BLOCK_SIZED, BLOCK_UNSIZED, BLOCK_CONTINUATION } block_type;
typedef struct {
    uint8_t *input, *output;
    size_t incap, outcap;
    size_t insize, outsize;
    off_t uoffset; // uncompressed offset
    lzma_check check;

    block_type btype;
} io_block_t;

bool read_block(bool force_stream, lzma_check check, off_t uoffset);
void block_capacity(io_block_t *ib, size_t incap, size_t outcap);

static void read_decode(io_block_t *ib) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_filter filters[LZMA_FILTERS_MAX + 1];
    lzma_block block = { .filters = filters, .check = LZMA_CHECK_NONE,
        .version = 0 };

    //pipeline_item_t *pi;

    //while (PIPELINE_STOP != queue_pop(gPipelineSplitQ, (void**)&pi)) {
    //    ib = (io_block_t*)(pi->data);

        block.header_size = lzma_block_header_size_decode(*(ib->input));
        block.check = ib->check;
        if (lzma_block_header_decode(&block, NULL, ib->input) != LZMA_OK)
            die("Error decoding block header");
        if (lzma_block_decoder(&stream, &block) != LZMA_OK)
            die("Error initializing block decode");

        stream.avail_in = ib->insize - block.header_size;
        stream.next_in = ib->input + block.header_size;
        stream.avail_out = ib->outcap;
        stream.next_out = ib->output;

        lzma_ret err = LZMA_OK;
        while (err != LZMA_STREAM_END) {
            if (err != LZMA_OK)
                die("Error decoding block");
            err = lzma_code(&stream, LZMA_FINISH);
        }

        ib->outsize = stream.next_out - ib->output;
        //queue_push(gPipelineMergeQ, PIPELINE_ITEM, pi);
        if (fwrite(ib->output, ib->outsize, 1, stdout) != 1)
            die("Can't write block");
    //}
    lzma_end(&stream);
}


static void read_start(void) {
    off_t offset = ftello(gInFile);

    lzma_index_iter iter;
    lzma_index_iter_init(&iter, gIndex);
    while (!lzma_index_iter_next(&iter, LZMA_INDEX_ITER_BLOCK)) {
        // Don't decode the file-index
        off_t boffset = iter.block.compressed_file_offset;
        size_t bsize = iter.block.total_size;

        debug("read: want %lu", iter.block.number_in_file);

        // Seek if needed, and get the data
        if (offset != boffset) {
            fseeko(gInFile, boffset, SEEK_SET);
            offset = boffset;
        }

        if (iter.block.uncompressed_size > MAXSPLITSIZE) { // must stream
            //if (gRbuf)
            //    rbuf_consume(gRbuf->insize); // clear
            read_block(true, iter.stream.flags->check,
                iter.block.uncompressed_file_offset);
        } else {
            // Get a block to work with
            io_block_t local_ib, *ib = &local_ib;
            memset(&local_ib, 0, sizeof local_ib);
            block_capacity(ib, bsize,
                iter.block.uncompressed_size);

            ib->insize = fread(ib->input, 1, bsize, gInFile);
            if (ib->insize < bsize)
                die("Error reading block contents");
            offset += bsize;
            ib->uoffset = iter.block.uncompressed_file_offset;
            ib->check = iter.stream.flags->check;
            ib->btype = BLOCK_SIZED; // Indexed blocks always sized

            debug("pipeline_split -> pipeline_dispatch -> queue_push(io_block): {\n"
                  "    incap = %zu\n"
                  "    outcap = %zu\n"
                  "    insize = %zu\n"
                  "    outsize = %zu\n"
                  "    uoffset = %zu\n"
                  "    check = %u\n"
                  "    type = %u\n"
                  "}\n",
                  ib->incap,
                  ib->outcap,
                  ib->insize,
                  ib->outsize,
                  ib->uoffset,
                  ib->check,
                  ib->btype
            );
            read_decode(ib);
        }
    }
    //pipeline_stop();
}
*/
typedef struct {
    //uint8_t *input, *output;
    //size_t incap, outcap;
    size_t insize, outsize;
    off_t inoffset, outoffset;
    //lzma_check check;
    //block_type btype;
} index_block_t;

static index_block_t *gIndexBlocks;
unsigned gIndexBlocksSize;

static void read_index_blocks(void) {
    lzma_index_iter iter;
    lzma_index_iter_init(&iter, gIndex);
    while (!lzma_index_iter_next(&iter, LZMA_INDEX_ITER_BLOCK)) {
        off_t boffset = iter.block.compressed_file_offset;
        fseeko(gInFile, boffset, SEEK_SET);

        if (iter.block.uncompressed_size > MAXSPLITSIZE) { // must stream
            die("Reading of big blocks is not implemented");
        } else {
            if ((gIndexBlocksSize & (gIndexBlocksSize - 1)) == 0) {
                gIndexBlocks = realloc(gIndexBlocks, (gIndexBlocksSize ? 2 * gIndexBlocksSize : 1) * sizeof *gIndexBlocks);
            }
            ++gIndexBlocksSize;

            // Get a block to work with
            index_block_t *ib = &gIndexBlocks[gIndexBlocksSize - 1];
            memset(ib, 0, sizeof *ib);
            ib->insize = iter.block.total_size;
            ib->outsize = iter.block.uncompressed_size;
            ib->inoffset = boffset;
            ib->outoffset = iter.block.uncompressed_file_offset;
            //ib->check = iter.stream.flags->check;
            //ib->insize = fread(ib->input, 1, bsize, gInFile);
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
    if (b - gIndexBlocks == gIndexBlocksSize - 1)
        return 0;
    if (b[1].outoffset <= a->outoffset)
        return 1;
    return 0;
}

__attribute((aligned(0x1000)))
static uint8_t seek_buf[16 << 10]; // 16 << 10

static int pixz_single_file_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    if (path[0] == '/') {
        if (strcmp(&path[1], gSingleFileDestName) == 0) {
            size_t len = gIndexBlocks[gIndexBlocksSize - 1].outoffset + gIndexBlocks[gIndexBlocksSize - 1].outsize;
            if (offset < len) {
                assert(size <= INT_MAX);
                if (offset + size > len)
                    size = len - offset;
#if 0
                memset(buf, 0, size);
#else
                index_block_t reference;
                reference.outoffset = offset;
                index_block_t *found = bsearch(&reference, gIndexBlocks, gIndexBlocksSize, sizeof *gIndexBlocks, index_block_find_outoffset);
                assert(found);

                lzma_ret err;
                lzma_stream stream = LZMA_STREAM_INIT;
                size_t remaining_size = size;
                do {
                    assert(found - gIndexBlocks < gIndexBlocksSize);
                    assert(found->outoffset <= offset);
                    assert(found - gIndexBlocks == gIndexBlocksSize - 1 || found[1].outoffset > offset);

                    uint8_t *input = malloc(found->insize);
                    fseeko(gInFile, found->inoffset, SEEK_SET);
                    size_t read = fread(input, 1, found->insize, gInFile);
                    assert(read == found->insize);

                    lzma_filter filters[LZMA_FILTERS_MAX + 1];
                    lzma_block block = { .filters = filters, .check = LZMA_CHECK_NONE, .version = 0 };

                    block.header_size = lzma_block_header_size_decode(input[0]);
                    //block.check = LZMA_CHECK_CRC32;
                    if (lzma_block_header_decode(&block, NULL, input) != LZMA_OK)
                        die("Error decoding block header");
                    if (lzma_block_decoder(&stream, &block) != LZMA_OK)
                        die("Error initializing block decode");

                    stream.avail_in = found->insize - block.header_size;
                    stream.next_in = input + block.header_size;

                    off_t block_offset = offset - found->outoffset;
                    if (block_offset != 0) {
                        do {
                            stream.next_out = seek_buf;
                            stream.avail_out = (sizeof seek_buf < block_offset ? sizeof seek_buf : block_offset);
                            block_offset -= stream.avail_out;
                            err = lzma_code(&stream, LZMA_FINISH);
                            if (err != LZMA_OK)
                                die("Error seeking block");
                        } while (block_offset);
                        assert(stream.total_out == offset - found->outoffset);
                    }

                    stream.avail_out = remaining_size;
                    stream.next_out = (uint8_t*)buf;

                    for (;;) {
                        err = lzma_code(&stream, LZMA_FINISH);
                        if (err == LZMA_BUF_ERROR && stream.next_out - (uint8_t*)buf == remaining_size)
                            break;
                        if (err == LZMA_STREAM_END) {
                            ++found;
                            break;
                        }
                        if (err != LZMA_OK)
                            die("Error decoding block");
                    }

                    offset += stream.next_out - (uint8_t*)buf;
                    remaining_size -= stream.next_out - (uint8_t*)buf;
                    buf += stream.next_out - (uint8_t*)buf;
                    free(input);
                } while (err == LZMA_STREAM_END && remaining_size);

                assert(remaining_size == 0);
                lzma_end(&stream);
#endif
            } else {
                size = 0;
            }
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
        gInputMap = mmap(hint, in_file_len, PROT_READ, MAP_PRIVATE, in_file_fd, 0);
        if (gInputMap == MAP_FAILED)
            die("Can't mmap: %d", errno);
        if (in_file_len >= 1 << 30 && ((size_t)gInputMap & ((1 << 30) - 1))) {
            if (hint == NULL)
                hint = gInputMap - ((size_t)gInputMap & ((1 << 30) - 1));
            else
                hint += 1 << 30;
            if (munmap(gInputMap, in_file_len))
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
