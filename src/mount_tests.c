#if 1

#include <stdio.h>
#include <assert.h>
#include <string.h>

int is_under_debugger(void) {
    // https://stackoverflow.com/questions/3596781/how-to-detect-if-the-current-process-is-being-run-by-gdb
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char buf[4000];
    size_t read = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    if (!read) return 0;

    assert(read < sizeof buf);
    buf[read] = '\0';

    static const char search_str[] = "TracerPid:";
    const char *tracer_pid_ptr = strstr(buf, search_str);
    if (!tracer_pid_ptr) return 0;

    int dbg_pid;
    if (sscanf(&tracer_pid_ptr[sizeof search_str - 1], " %d", &dbg_pid) == 1 && dbg_pid > 0)
        return 1;

    return 0;
}

#define TESTS 1
#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <lzma.h>
#undef lzma_block_header_size_decode
#define lzma_block_header_size_decode(byte) 0
#define lzma_block_header_decode(b, a, i) (LZMA_OK)
#define lzma_block_decoder(s, b) (LZMA_OK)
#define lzma_code(s, a) test_lzma_code(s, a)
#define lzma_end(s) (void)0

static char *uncompressed_data;
static size_t uncompressed_data_len = 1100;

struct test_lzma_code_call_t {
    size_t offset, size;
};
#define ASSERT_TEST_LZMA_CODE_CALL(i, off, sz) do { \
        assert(test_lzma_code_calls[i].offset == off); \
        assert(test_lzma_code_calls[i].size == sz); \
    } while (0)
static struct test_lzma_code_call_t test_lzma_code_calls[100];
static unsigned test_lzma_code_calls_length;

#define pixz_mount_main test_pixz_mount_main

static lzma_ret test_lzma_code(lzma_stream *strm, lzma_action action);

#define DECOMPRESSED_CACHE_BLOCK_SIZE 128

#include "mount.c"

static lzma_ret test_lzma_code(lzma_stream *strm, lzma_action action) {
    assert(action == LZMA_FINISH);
    assert((char*)strm->next_in >= uncompressed_data);
    assert((char*)strm->next_in + strm->avail_in <= uncompressed_data + uncompressed_data_len);
    size_t offset = (char*)strm->next_in - uncompressed_data;

    index_block_t *reference = (void*)&offset - ((char*)&reference->outoffset - (char*)reference);
    index_block_t *index_block = bsearch(reference, gIndexBlocks, gIndexBlocksSize, sizeof *gIndexBlocks, index_block_find_outoffset);
    assert(index_block);

    assert(gIndexBlocks <= index_block && index_block < gIndexBlocks + gIndexBlocksSize);
    assert(index_block->outoffset <= offset);
    assert(offset < index_block->outoffset + index_block->outsize);
    assert(index_block - gIndexBlocks == gIndexBlocksSize - 1 || index_block[1].outoffset > offset);

    size_t size = strm->avail_out <= strm->avail_in ? strm->avail_out : strm->avail_in;
    lzma_ret res = size == strm->avail_in ? LZMA_STREAM_END : LZMA_OK;

    assert((char*)strm->next_in + size <= uncompressed_data + uncompressed_data_len);
    assert((char*)strm->next_in >= uncompressed_data + index_block->inoffset);
    assert((char*)strm->next_in + size <= uncompressed_data + index_block->inoffset + index_block->insize);
    assert(test_lzma_code_calls_length < sizeof test_lzma_code_calls / sizeof *test_lzma_code_calls);
    assert(offset < uncompressed_data_len);
    test_lzma_code_calls[test_lzma_code_calls_length].offset = offset;
    test_lzma_code_calls[test_lzma_code_calls_length].size = size;
    printf("  test_lzma_code(%u, %zu, %zu)\n", test_lzma_code_calls_length, (char*)strm->next_in - uncompressed_data, size);
    assert(strm->reserved_int3 == offset - index_block->outoffset);
    strm->reserved_int3 += size;
    assert((strm->reserved_int3 == index_block->outsize) == (res == LZMA_STREAM_END));
    ++test_lzma_code_calls_length;

    memcpy(strm->next_out, strm->next_in, size);
    strm->next_in += size;
    strm->next_out += size;
    strm->avail_in -= size;
    strm->avail_out -= size;
    strm->total_out += size;
    return res;
}

#define ASSERT_TREE_CONTAINS_BLOCK(tree, off, sz) do { \
        struct tree_traverse_context search_ctx; tree_traverse_context_init(&search_ctx);; \
        struct tree_node *found_node = tree_search((tree)->root, (off), &search_ctx); \
        assert(found_node); \
        assert(found_node->key_value.offset == (off)); \
        assert(found_node->key_value.data->size == (sz)); \
    } while (0)

static void tree_tests(void);

void pixz_tests(void) {
    tree_tests();
    gSingleFileDestName = "test";
    static const index_block_t test_index_blocks[] = {
        {.insize = 1000, .outsize = 1000, .inoffset = 0, .outoffset = 0, LZMA_STREAM_INIT},
        {.insize = 100, .outsize = 100, .inoffset = 1000, .outoffset = 1000, LZMA_STREAM_INIT},
    };
    //gIndexBlocks = (index_block_t *)test_index_blocks;
    gIndexBlocksSize = sizeof test_index_blocks / sizeof *test_index_blocks;
    gIndexBlocks = malloc(gIndexBlocksSize * sizeof *gIndexBlocks);
    memcpy(gIndexBlocks, test_index_blocks, gIndexBlocksSize * sizeof *gIndexBlocks);
    assert(uncompressed_data_len == gIndexBlocks[gIndexBlocksSize-1].outoffset + gIndexBlocks[gIndexBlocksSize-1].outsize);
    uncompressed_data = malloc(uncompressed_data_len);
    memset(uncompressed_data, '\n', uncompressed_data_len);
    for (size_t i = 0; i < uncompressed_data_len; ++i) {
        char buf[30];
        int line_size = sprintf(buf, ":%lu", i);
        if (i + line_size < uncompressed_data_len)
            memcpy(&uncompressed_data[i], buf, line_size);
        else
            memset(&uncompressed_data[i], '.', uncompressed_data_len - i - 1);
        i += line_size;
    }
    gInputMMap = (uint8_t*)uncompressed_data;

    char *test_buf = malloc(uncompressed_data_len);

    unsigned offset, size;

    {
        assert(options.read_ahead == 1);
        assert(options.read_ahead_no_split_at_read_start_offsets == 1);

        printf("test (offset = %u, size = %u)\n", offset = 4, size = 8);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 1);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 0, 128);
        assert(test_lzma_code_calls_length == 1);
        ASSERT_TEST_LZMA_CODE_CALL(0, 0, 128);

        printf("test (offset = %u, size = %u)\n", offset = 500, size = 25);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 5);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 0, 128);
        assert(test_lzma_code_calls_length == 5);
        ASSERT_TEST_LZMA_CODE_CALL(1, 128, 128);
        ASSERT_TEST_LZMA_CODE_CALL(2, 256, 128);
        ASSERT_TEST_LZMA_CODE_CALL(3, 384, 128);
        ASSERT_TEST_LZMA_CODE_CALL(4, 512, 128);

        options.read_ahead = 0;
        options.read_ahead_no_split_at_read_start_offsets = 0;
        tree_delete(&decompressed_blocks, 256); cache_size -= 128;

        printf("test (offset = %u, size = %u)\n", offset = 260, size = 1);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 6);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 256, 4);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 260, 1);
        assert(test_lzma_code_calls_length == 9);
        ASSERT_TEST_LZMA_CODE_CALL(5, 0, 128);
        ASSERT_TEST_LZMA_CODE_CALL(6, 128, 128);
        ASSERT_TEST_LZMA_CODE_CALL(7, 256, 4);
        ASSERT_TEST_LZMA_CODE_CALL(8, 260, 1);

        tree_delete(&decompressed_blocks, 256); cache_size -= 4;
        tree_delete(&decompressed_blocks, 0); cache_size -= 128;

        printf("test (offset = %u, size = %u)\n", offset = 1, size = 1);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 6);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 0, 1);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 1, 1);
        assert(test_lzma_code_calls_length == 11);
        ASSERT_TEST_LZMA_CODE_CALL(9, 0, 1);
        ASSERT_TEST_LZMA_CODE_CALL(10, 1, 1);

        options.read_ahead = 1;
        options.read_ahead_no_split_at_read_start_offsets = 1;
        tree_delete(&decompressed_blocks, 0); cache_size -= 1;

        printf("test (offset = %u, size = %u)\n", offset = 900, size = 1);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 11);
        assert(test_lzma_code_calls_length == 21);

        tree_delete(&decompressed_blocks, 260); cache_size -= 1;
        tree_delete(&decompressed_blocks, 768); cache_size -= 128;

        printf("test (offset = %u, size = %u)\n", offset = 800, size = 220);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 13);
        assert(test_lzma_code_calls_length == 33);
        ASSERT_TEST_LZMA_CODE_CALL(21, 0, 1);
        ASSERT_TEST_LZMA_CODE_CALL(22, 1, 1);
        ASSERT_TEST_LZMA_CODE_CALL(23, 2, 126);
        ASSERT_TEST_LZMA_CODE_CALL(24, 128, 128);
        ASSERT_TEST_LZMA_CODE_CALL(25, 256, 4);
        ASSERT_TEST_LZMA_CODE_CALL(26, 260, 1);
        ASSERT_TEST_LZMA_CODE_CALL(27, 261, 123);
        ASSERT_TEST_LZMA_CODE_CALL(28, 384, 128);
        ASSERT_TEST_LZMA_CODE_CALL(29, 512, 128);
        ASSERT_TEST_LZMA_CODE_CALL(30, 640, 128);
        ASSERT_TEST_LZMA_CODE_CALL(31, 768, 128);
        ASSERT_TEST_LZMA_CODE_CALL(32, 1000, 100);

        printf("test (offset = %u, size = %u)\n", offset = 0, size = 1100);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 13);
        assert(test_lzma_code_calls_length == 33);
    }

    for (unsigned i = 0; decompressed_blocks.length; ++i) {
        assert(i < test_lzma_code_calls_length);
        tree_delete(&decompressed_blocks, test_lzma_code_calls[i].offset);
    }
    memset(&decompressed_blocks, 0, sizeof decompressed_blocks); cache_size = 0;
    memcpy(gIndexBlocks, test_index_blocks, gIndexBlocksSize * sizeof *gIndexBlocks);
    test_lzma_code_calls_length = 0;

    options.read_ahead_no_split_at_read_start_offsets = 0;
    options.read_ahead = 1;

    {
        printf("test (offset = %u, size = %u)\n", offset = 4, size = 8);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 0, 4);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 4, 128);
        assert(test_lzma_code_calls_length == 2);
        ASSERT_TEST_LZMA_CODE_CALL(0, 0, 4);
        ASSERT_TEST_LZMA_CODE_CALL(1, 4, 128);

        printf("test (offset = %u, size = %u)\n", offset = 500, size = 16);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 5);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 132, 128);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 260, 240);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 500, 128);
        assert(test_lzma_code_calls_length == 5);
        ASSERT_TEST_LZMA_CODE_CALL(2, 132, 128);
        ASSERT_TEST_LZMA_CODE_CALL(3, 260, 240);
        ASSERT_TEST_LZMA_CODE_CALL(4, 500, 128);
        tree_delete(&decompressed_blocks, 260); cache_size -= 240;

        printf("test (offset = %u, size = %u)\n", offset = 490, size = 16);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 6);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 260, 230);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 260, 230);
        assert(test_lzma_code_calls_length == 10);
        ASSERT_TEST_LZMA_CODE_CALL(5, 0, 4);
        ASSERT_TEST_LZMA_CODE_CALL(6, 4, 128);
        ASSERT_TEST_LZMA_CODE_CALL(7, 132, 128);
        ASSERT_TEST_LZMA_CODE_CALL(8, 260, 230);
        ASSERT_TEST_LZMA_CODE_CALL(9, 490, 10);

        // [0..4) [4..132) [132..260) [260..490) [490..10) [500, 628)
        printf("test (offset = %u, size = %u)\n", offset = test_index_blocks[0].outsize - 4, size = 8);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
    }

    for (unsigned i = 0; decompressed_blocks.length; ++i) {
        assert(i < test_lzma_code_calls_length);
        tree_delete(&decompressed_blocks, test_lzma_code_calls[i].offset);
    }
    memset(&decompressed_blocks, 0, sizeof decompressed_blocks); cache_size = 0;
    memcpy(gIndexBlocks, test_index_blocks, gIndexBlocksSize * sizeof *gIndexBlocks);
    test_lzma_code_calls_length = 0;

    options.read_ahead = 0;

    for (int i = 1; i <= 2; ++i) {
        printf("test (offset = %u, size = %u) time %d\n", offset = 10, size = 30, i);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 0, 10);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 10, 30);
        assert(test_lzma_code_calls_length == 2);
        ASSERT_TEST_LZMA_CODE_CALL(0, 0, 10);
        ASSERT_TEST_LZMA_CODE_CALL(1, 10, 30);
    }

    {
        printf("test (offset = %u, size = %u) cached\n", offset = 0, size = 10);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        assert(test_lzma_code_calls_length == 2);
    }

    {
        printf("test (offset = %u, size = %u) cached, partial left bound\n", offset = 0, size = 6);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        assert(test_lzma_code_calls_length == 2);
    }

    {
        printf("test (offset = %u, size = %u) cached, partial right bound\n", offset = 16, size = 24);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        assert(test_lzma_code_calls_length == 2);
    }

    {
        printf("test (offset = %u, size = %u) cached, partial\n", offset = 6, size = 2);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        assert(test_lzma_code_calls_length == 2);
    }

    {
        printf("test (offset = %u, size = %u) cached, partial\n", offset = 15, size = 20);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        assert(test_lzma_code_calls_length == 2);
    }

    {
        printf("test (offset = %u, size = %u) cached two blocks\n", offset = 0, size = 40);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 2);
        assert(test_lzma_code_calls_length == 2);
    }

    for (int i = 1; i <= 2; ++i) {
        printf("test (offset = %u, size = %u) cached two blocks + new block, time %d\n", offset = 6, size = 94, i);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 3);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 40, 60);
        assert(test_lzma_code_calls_length == 3);
        ASSERT_TEST_LZMA_CODE_CALL(2, 40, 60);
    }

    {
        printf("test (offset = %u, size = %u) fill non-cached hole\n", offset = 110, size = 40);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 5);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 100, 10);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 110, 40);
        assert(test_lzma_code_calls_length == 5);
        ASSERT_TEST_LZMA_CODE_CALL(3, 100, 10);
        ASSERT_TEST_LZMA_CODE_CALL(4, 110, 40);
    }

    {
        printf("test (offset = %u, size = %u)\n", offset = 200, size = 40);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 7);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 150, 50);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 200, 40);
        assert(test_lzma_code_calls_length == 7);
        ASSERT_TEST_LZMA_CODE_CALL(5, 150, 50);
        ASSERT_TEST_LZMA_CODE_CALL(6, 200, 40);
    }

    {
        // make 2 holes
        // [0..10) [10..40) [40..100) [100..110) [110..150) [150, 200) [200, 40)
        //          delete                                    delete
        tree_delete(&decompressed_blocks, 10); cache_size -= 30;
        tree_delete(&decompressed_blocks, 150); cache_size -= 50;
        assert(decompressed_blocks.length == 5);

        printf("test (offset = %u, size = %u) over 2 non-cached holes\n", offset = 170, size = 25);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 8);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 10, 30);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 150, 20);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 170, 25);
        assert(test_lzma_code_calls_length == 14);
        ASSERT_TEST_LZMA_CODE_CALL(7, 0, 10);
        ASSERT_TEST_LZMA_CODE_CALL(8, 10, 30);
        ASSERT_TEST_LZMA_CODE_CALL(9, 40, 60);
        ASSERT_TEST_LZMA_CODE_CALL(10, 100, 10);
        ASSERT_TEST_LZMA_CODE_CALL(11, 110, 40);
        ASSERT_TEST_LZMA_CODE_CALL(12, 150, 20);
        ASSERT_TEST_LZMA_CODE_CALL(13, 170, 25);
    }

    {
        // make 2 holes
        // [0..10) [10..40) [40..100) [100..110) [110..150) [150, 170) [170, 195) ... [200, 240)
        //   del               del        del
        tree_delete(&decompressed_blocks, 0); cache_size -= 10;
        tree_delete(&decompressed_blocks, 40); cache_size -= 60;
        tree_delete(&decompressed_blocks, 100); cache_size -= 10;
        assert(decompressed_blocks.length == 5);

        printf("test (offset = %u, size = %u) cached\n", offset = 10, size = 30);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 5);
        assert(test_lzma_code_calls_length == 14);
    }

    {
        printf("test (offset = %u, size = %u) cached, partial\n", offset = 120, size = 70);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 5);
        assert(test_lzma_code_calls_length == 14);
    }

    {
        // ... [10..40) ... [110..150) [150, 170) [170, 195) ... [200, 240)
        printf("test (offset = %u, size = %u) over non-cached hole\n", offset = 195, size = 35);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 6);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 195, 5);
        assert(test_lzma_code_calls_length == 15);
        ASSERT_TEST_LZMA_CODE_CALL(14, 195, 5);
    }

    {
        // ... [10..40) ... [110..150) [150, 170) [170, 195) [195, 5) [200, 240)
        printf("test (offset = %u, size = %u) over non-cached hole, reset stream\n", offset = 30, size = 220);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
        assert(decompressed_blocks.length == 9);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 0, 10);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 40, 70);
        ASSERT_TREE_CONTAINS_BLOCK(&decompressed_blocks, 240, 10);
        assert(test_lzma_code_calls_length == 24);
        ASSERT_TEST_LZMA_CODE_CALL(15, 0, 10);
        ASSERT_TEST_LZMA_CODE_CALL(16, 10, 30);
        ASSERT_TEST_LZMA_CODE_CALL(17, 40, 70);
        ASSERT_TEST_LZMA_CODE_CALL(18, 110, 40);
        ASSERT_TEST_LZMA_CODE_CALL(19, 150, 20);
        ASSERT_TEST_LZMA_CODE_CALL(20, 170, 25);
        ASSERT_TEST_LZMA_CODE_CALL(21, 195, 5);
        ASSERT_TEST_LZMA_CODE_CALL(22, 200, 40);
        ASSERT_TEST_LZMA_CODE_CALL(23, 240, 10);
    }

    for (unsigned i = 0; decompressed_blocks.length; ++i) {
        assert(i < test_lzma_code_calls_length);
        tree_delete(&decompressed_blocks, test_lzma_code_calls[i].offset);
    }
    memset(&decompressed_blocks, 0, sizeof decompressed_blocks); cache_size = 0;
    memcpy(gIndexBlocks, test_index_blocks, gIndexBlocksSize * sizeof *gIndexBlocks);
    test_lzma_code_calls_length = 0;

    {
        printf("test (offset = %u, size = %u)\n", offset = 4, size = 8);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = 0, size = 16);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = 0, size = 32);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = 0, size = 64);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = 4, size = 32);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = 32, size = 32);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = 64, size = 4);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);

        printf("test (offset = %u, size = %u)\n", offset = test_index_blocks[0].outsize - 4, size = 8);
        memset(test_buf, 0, uncompressed_data_len);
        assert(pixz_single_file_fuse_read("/test", test_buf, size, offset, NULL) == size);
        assert(memcmp(test_buf, uncompressed_data + offset, size) == 0);
    }

    for (unsigned i = 0; decompressed_blocks.length; ++i) {
        assert(i < test_lzma_code_calls_length);
        tree_delete(&decompressed_blocks, test_lzma_code_calls[i].offset);
    }
    //tree_free(&decompressed_blocks);
    memset(&decompressed_blocks, 0, sizeof decompressed_blocks); cache_size = 0;
    free(test_buf);
    gSingleFileDestName = NULL;
    free(gIndexBlocks);
    gIndexBlocks = NULL;
    gIndexBlocksSize = 0;
    gInputMMap = NULL;
    free(uncompressed_data);
    printf("ok\n");
}

enum {
  BLACK = 0,
  RED = 1
};

static TREE_NODE_KEY_VALUE_TYPE keys[15];
static unsigned keys_len;

static TREE_NODE_KEY_VALUE_TYPE *key(size_t k) {
    assert(keys_len < sizeof keys / sizeof *key);
    keys[keys_len].offset = k;
    keys[keys_len].data = malloc((char*)&keys[keys_len].data->bytes - (char*)keys[keys_len].data);
    keys[keys_len].data->size = 1;
    return &keys[keys_len++];
}

static int tree_tests_set_parent(void *data, struct tree_node *node) {
    if (LEFT(node)) PARENT_SET(LEFT(node), node);
    if (RIGHT(node)) PARENT_SET(RIGHT(node), node);
    return 0;
}

static void tree_tests(void) {
    for (int i = 0; i < 15; ++i) {
        keys_len = 0;
        struct tree local_tree = {
            tree_new_node(
                tree_new_node(
                    tree_new_node(
                        tree_new_node(
                            NULL,
                            NULL,
                            NULL, BLACK, key(1)),
                        tree_new_node(
                            NULL,
                            NULL,
                            NULL, BLACK, key(9)),
                        NULL, BLACK, key(5)),
                    tree_new_node(
                        tree_new_node(
                            NULL,
                            NULL,
                            NULL, BLACK, key(55)),
                        tree_new_node(
                            tree_new_node(
                                NULL,
                                NULL,
                                NULL, BLACK, key(65)),
                            tree_new_node(
                                tree_new_node(
                                    NULL,
                                    NULL,
                                    NULL, RED, key(80)),
                                NULL,
                                NULL, BLACK, key(90)),
                            NULL, RED, key(70)),
                        NULL, BLACK, key(60)),
                    NULL, RED, key(50)),
                tree_new_node(
                    tree_new_node(
                        NULL,
                        NULL,
                        NULL, BLACK, key(110)),
                    tree_new_node(
                        NULL,
                        tree_new_node(
                            NULL,
                            NULL,
                            NULL, RED, key(140)),
                        NULL, BLACK, key(130)),
                    NULL, BLACK, key(120)),
                NULL, BLACK, key(100)),
            15
        }, *tree = &decompressed_blocks;
        memcpy(tree, &local_tree, sizeof decompressed_blocks);
        tree_iterate_parameterized(tree, tree_tests_set_parent, NULL, 1);
        tree_write_dot_graph(tree, NULL, NULL, NULL, NULL, NULL);
        tree_check(tree);
        assert(tree_delete(tree, keys[i].offset));
        tree_write_dot_graph(tree, NULL, NULL, NULL, NULL, NULL);
        tree_check(tree);
        tree_free(tree);
    }
    memset(&decompressed_blocks, 0, sizeof decompressed_blocks);
}

#endif
