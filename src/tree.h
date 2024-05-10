struct tree_node {
    struct tree_node *_left, *_right, *_parent;
    TREE_NODE_KEY_VALUE_TYPE key_value;
};

#define LEFT(node) ((node)->_left)
#define LEFT_SET(node, r) (void)((node)->_left = (r))
#define RIGHT(node) ((node)->_right)
#define RIGHT_SET(node, p) (void)((node)->_right = (p))
#define PARENT(node) ((struct tree_node *)((size_t)(node)->_parent & ~(size_t)1))
#define PARENT_SET(node, p) ((void)(*(size_t*)&(node)->_parent = (size_t)(p) | ((size_t)(node)->_parent & 1)))
#define RED(node) ((size_t)(node)->_parent & 1)
#define RED_SET(node, red) ((void)(*(size_t*)&(node)->_parent &= ~(size_t)1, *(size_t*)&(node)->_parent |= (red)))

struct tree {
    struct tree_node *root;
    size_t length;
};

#if TESTS || 1
#ifndef TREE_DO_CHECK
#define TREE_DO_CHECK 1
#endif

#ifndef WRITE_DOT_GRAPH
#define WRITE_DOT_GRAPH 0
#endif

#ifndef WRITE_PREV_DOT_GRAPH
#define WRITE_PREV_DOT_GRAPH 1
#endif

#ifndef TREE_DO_CHECK_PATHS
#define TREE_DO_CHECK_PATHS 1
#endif

static const char dot_graph_path[] = "/tmp/rbtree.dot";
#if WRITE_PREV_DOT_GRAPH
static const char dot_graph_path_bak[] = "/tmp/rbtree.dot.bak";
static const char dot_graph_path_prev[] = "/tmp/rbtree-prev.dot";
#endif

static void tree_write_dot_graph(struct tree *tree,
                                 struct tree_node *highlight_node,
                                 struct tree_node *highlight_parent,
                                 struct tree_node *highlight_grandparent,
                                 struct tree_node *highlight_uncle,
                                 struct tree_node *highlight_sibling)
{
    struct tree_node *node = tree->root, *stack[100];
    int stack_length = 1; stack[0] = NULL;
#if WRITE_PREV_DOT_GRAPH
    rename(dot_graph_path, dot_graph_path_bak);
#endif
    FILE *f = fopen(dot_graph_path, "w"); assert(f);
    // https://stackoverflow.com/questions/23429600/how-do-i-make-a-dot-graph-representing-a-binary-tree-more-symmetric
    fprintf(f, "digraph rbtree {\n");
    fprintf(f, "  label=\"length = %zu\";\n", tree->length);
    fprintf(f, "  labelloc=top;\n  labeljust=left;\n");
    while (node) {
        char label[60], p[30];
        sprintf(p, PARENT(node) ? "p:%zu" : " p:NULL", PARENT(node) ? TREE_NODE_KEY_VALUE_KEY(PARENT(node)->key_value) : 0);
        if (node == highlight_node) sprintf(label, ",label=\"%zu %s (N)\"", TREE_NODE_KEY_VALUE_KEY(node->key_value), p);
        else if (node == highlight_parent) sprintf(label, ",label=\"%zu %s (P)\"", TREE_NODE_KEY_VALUE_KEY(node->key_value), p);
        else if (node == highlight_grandparent) sprintf(label, ",label=\"%zu %s (G)\"", TREE_NODE_KEY_VALUE_KEY(node->key_value), p);
        else if (node == highlight_uncle) sprintf(label, ",label=\"%zu %s (U)\"", TREE_NODE_KEY_VALUE_KEY(node->key_value), p);
        else if (node == highlight_sibling) sprintf(label, ",label=\"%zu %s (S)\"", TREE_NODE_KEY_VALUE_KEY(node->key_value), p);
        else sprintf(label, ",label=\"%zu %s\"", TREE_NODE_KEY_VALUE_KEY(node->key_value), p);
        fprintf(f, "  %zu [color=%s,fontsize=14,fontcolor=white,style=filled%s];\n", TREE_NODE_KEY_VALUE_KEY(node->key_value), RED(node) ? "red" : "black", label);
        if (!LEFT(node))
            fprintf(f, "  { node[style=invis, label=\"\"]; \"%zu_l\"; }", TREE_NODE_KEY_VALUE_KEY(node->key_value));
        fprintf(f, "  { node[style=invis, label=\"\"]; \"%zu_m\"; }", TREE_NODE_KEY_VALUE_KEY(node->key_value));
        if (!RIGHT(node))
            fprintf(f, "  { node[style=invis, label=\"\"]; \"%zu_r\"; }", TREE_NODE_KEY_VALUE_KEY(node->key_value));
        fprintf(f, "  { edge[style=invis]; rank=same; \"");
        fprintf(f, LEFT(node) ? "%zu" : "%zu_l", LEFT(node) ? TREE_NODE_KEY_VALUE_KEY(LEFT(node)->key_value) : TREE_NODE_KEY_VALUE_KEY(node->key_value));
        fprintf(f, "\" -> \"%zu_m\" -> \"", TREE_NODE_KEY_VALUE_KEY(node->key_value));
        fprintf(f, RIGHT(node) ? "%zu" : "%zu_r", RIGHT(node) ? TREE_NODE_KEY_VALUE_KEY(RIGHT(node)->key_value) : TREE_NODE_KEY_VALUE_KEY(node->key_value));
        fprintf(f, "\"; }\n");
        fprintf(f, "  { edge[style=invis]; %zu -> \"%zu_m\"; }\n", TREE_NODE_KEY_VALUE_KEY(node->key_value), TREE_NODE_KEY_VALUE_KEY(node->key_value));
        if (RIGHT(node)) {
            assert(stack_length < sizeof stack / sizeof *stack);
            stack[stack_length++] = RIGHT(node);
            fprintf(f, "  %zu -> %zu;\n", TREE_NODE_KEY_VALUE_KEY(node->key_value), TREE_NODE_KEY_VALUE_KEY(RIGHT(node)->key_value));
        } else {
            fprintf(f, "  { edge[style=invis]; %zu -> \"%zu_r\"; }\n", TREE_NODE_KEY_VALUE_KEY(node->key_value), TREE_NODE_KEY_VALUE_KEY(node->key_value));
        }
        if (LEFT(node)) {
            assert(stack_length < sizeof stack / sizeof *stack);
            stack[stack_length++] = LEFT(node);
            fprintf(f, "  %zu -> %zu;\n", TREE_NODE_KEY_VALUE_KEY(node->key_value), TREE_NODE_KEY_VALUE_KEY(LEFT(node)->key_value));
        } else {
            fprintf(f, "  { edge[style=invis]; %zu -> \"%zu_l\"; }\n", TREE_NODE_KEY_VALUE_KEY(node->key_value), TREE_NODE_KEY_VALUE_KEY(node->key_value));
        }
        node = stack[--stack_length];
    }
    fprintf(f, "}\n");
    fclose(f);
#if WRITE_PREV_DOT_GRAPH
    char s[200];
    sprintf(s, "test -e %s && { diff -q %s %s >/dev/null || mv %s %s; } || :",
            dot_graph_path_bak,
            dot_graph_path_bak, dot_graph_path,
            dot_graph_path_bak, dot_graph_path_prev);
    assert(system(s) == 0);
#endif
}

static void tree_check_parameterized(struct tree *tree, int no_check_keys) {
#if WRITE_DOT_GRAPH
    tree_write_dot_graph(tree, NULL, NULL, NULL, NULL, NULL);
#endif
    size_t length = 0;
    struct tree_node *node = tree->root;
    assert(!node || !RED(node));
    struct stack {struct tree_node *node; int height;} stack[100];
    stack[0].node = NULL; stack[0].height = 0;
    int stack_length = 1, height = 0;
    struct path {struct tree_node *node; int black_count;} path[50];
    assert((tree->root == NULL) == (tree->length == 0));
    while (node) {
        ++length;
        for (int child_idx = 0; child_idx < 2; ++child_idx) {
            struct tree_node *child = child_idx == 0 ? LEFT(node) : RIGHT(node);
            if (child) {
                if (child_idx == 0)
                    assert(TREE_NODE_KEY_VALUE_KEY(LEFT(node)->key_value) <= TREE_NODE_KEY_VALUE_KEY(node->key_value) || no_check_keys);
                else
                    assert(TREE_NODE_KEY_VALUE_KEY(RIGHT(node)->key_value) >= TREE_NODE_KEY_VALUE_KEY(node->key_value) || no_check_keys);
                assert(stack_length < (int)(sizeof stack / sizeof *stack));
                assert(height + 1 < (int)(sizeof path / sizeof *path));
                stack[stack_length].height = height + 1;
                stack[stack_length++].node = child;
                assert(!RED(node) || !RED(child));
                assert(node == PARENT(child));
            }
        }
        path[height].node = node;
        path[height].black_count = -1;
#if TREE_DO_CHECK_PATHS
        for (int i = height - 1; i >= 0; --i) {
            if (path[i+1].node == LEFT(path[i].node)) {
                assert(TREE_NODE_KEY_VALUE_KEY(node->key_value) <= TREE_NODE_KEY_VALUE_KEY(path[i].node->key_value) || no_check_keys);
            } else {
                assert(path[i+1].node == RIGHT(path[i].node));
                assert(TREE_NODE_KEY_VALUE_KEY(node->key_value) >= TREE_NODE_KEY_VALUE_KEY(path[i].node->key_value) || no_check_keys);
            }
        }
        if (!LEFT(node) || !RIGHT(node)) {
            for (int i = height, black_count = 0; i >= 0; --i) {
                if (!RED(path[i].node))
                    ++black_count;
                if (path[i].black_count >= 0)
                    assert(path[i].black_count == black_count);
                else
                    path[i].black_count = black_count;
            }
        }
#endif
        assert(stack_length > 0);
        node = stack[--stack_length].node;
        assert(stack[stack_length].height <= height + 1);
        height = stack[stack_length].height;
    }
    assert(length == tree->length);
}

static void tree_check(struct tree *tree) {
    tree_check_parameterized(tree, 0);
}
#endif

static void tree_free(struct tree *tree) {
    struct tree_node *node = tree->root, *stack[100];
    int stack_length = 1; stack[0] = NULL;
    while (node) {
        struct tree_node *left = LEFT(node), *right = RIGHT(node);
        if (left) {
            assert(stack_length < (int)(sizeof stack / sizeof *stack));
            stack[stack_length++] = left;
        }
        TREE_NODE_FREE(node);
        free(node);
        if (right)
            node = right;
        else
            node = stack[--stack_length];
    }
}

static struct tree_node *tree_new_node(struct tree_node *left, struct tree_node *right, struct tree_node *parent, int red, TREE_NODE_KEY_VALUE_TYPE *key_value) {
    struct tree_node *node = malloc(sizeof *node);
    assert(node); assert(((size_t)node & 1) == 0);
    LEFT_SET(node, left);
    RIGHT_SET(node, right);
    PARENT_SET(node, parent);
    RED_SET(node, red);
    memcpy(&node->key_value, key_value, sizeof node->key_value);
    return node;
}

struct tree_traverse_context {
    struct tree_node *parent;
};

static struct tree_node *tree_search(struct tree_node *node, TREE_NODE_KEY_TYPE key, struct tree_traverse_context *traverse_context) {
    struct tree_node *parent = NULL;
    while (node) {
        TREE_NODE_KEY_TYPE node_key = TREE_NODE_KEY_VALUE_KEY(node->key_value);
        int cmp = TREE_NODE_KEY_CMP(key, node_key);
        if (cmp == 0)
            break;
        parent = node;
        if (cmp > 0)
            node = RIGHT(node);
        else
            node = LEFT(node);
    }
    if (traverse_context)
        traverse_context->parent = parent;
    return node;
}

enum tree_traverse_context_action {
    TREE_TRAVERSE_DO_NOT_UPDATE_CONTEXT,
    TREE_TRAVERSE_UPDATE_CONTEXT
};

enum tree_traverse_direction {
    TREE_TRAVERSE_BACKWARD,
    TREE_TRAVERSE_FORWARD
};

static struct tree_node *tree_traverse_iterate(struct tree_node *node, TREE_NODE_KEY_TYPE key,
                                               struct tree_traverse_context *traverse_context,
                                               enum tree_traverse_context_action update_context,
                                               enum tree_traverse_direction forward)
{
    struct tree_node *parent = node ? PARENT(node) : traverse_context->parent;
    if (node && (forward ? RIGHT(node) : LEFT(node))) {
        parent = node;
        node = forward ? RIGHT(node) : LEFT(node);
        while (forward ? LEFT(node) : RIGHT(node)) {
            parent = node;
            node = forward ? LEFT(node) : RIGHT(node);
        }
    } else if (node && parent) {
        struct tree_node *search_node = node;
        for (;;) {
            assert(search_node == LEFT(parent) || search_node == RIGHT(parent));
            if (search_node == (forward ? LEFT(parent) : RIGHT(parent))) {
                node = parent; parent = PARENT(node);
                break;
            } else {
                search_node = parent;
                if ((parent = PARENT(search_node)) == NULL) {
                    parent = node; node = NULL;
                    break;
                }
            }
        }
    } else if (!node && parent) {
        for (;;) {
            assert(node == LEFT(parent) || node == RIGHT(parent));
            int cmp = TREE_NODE_KEY_CMP(key, TREE_NODE_KEY_VALUE_KEY(parent->key_value));
            node = parent; parent = PARENT(node);
            if (cmp != 0 && (cmp > 0) == forward) {
                if (!parent)
                    return NULL;
            } else {
                break;
            }
        }
    } else {
        if (node)
            parent = node;
        node = NULL;
    }
    if (update_context)
        traverse_context->parent = parent;
    return node;
}

static struct tree_node *tree_next(struct tree_node *node, TREE_NODE_KEY_TYPE key,
                                   struct tree_traverse_context *traverse_context,
                                   enum tree_traverse_context_action update_context)
{
    return tree_traverse_iterate(node, key, traverse_context, update_context, TREE_TRAVERSE_FORWARD);
}

static struct tree_node *tree_previous(struct tree_node *node, TREE_NODE_KEY_TYPE key,
                                       struct tree_traverse_context *traverse_context,
                                       enum tree_traverse_context_action update_context)
{
    return tree_traverse_iterate(node, key, traverse_context, update_context, TREE_TRAVERSE_BACKWARD);
}

static void tree_traverse_context_init(struct tree_traverse_context *traverse_context) {
    traverse_context->parent = NULL;
}

/*static void tree_traverse_context_copy(struct tree_traverse_context *traverse_context, const struct tree_traverse_context *traverse_context2) {
    traverse_context->parent = traverse_context2->parent;
}*/

static void tree_traverse_context_equals(struct tree_traverse_context *traverse_context, const struct tree_traverse_context *traverse_context2) {
    assert(traverse_context->parent == traverse_context2->parent);
}

static struct tree_node *tree_insert(struct tree *tree, TREE_NODE_KEY_VALUE_TYPE *key_value, struct tree_traverse_context *traverse_context) {
    TREE_NODE_KEY_TYPE key = TREE_NODE_KEY_VALUE_KEY(*key_value);
    //struct tree_node *found_node = tree_search(tree->root, key, path, &path_free_length);
    //if (found_node)
    //    return found_node;
    struct tree_traverse_context search_context;
    if (!traverse_context) {
        tree_traverse_context_init(&search_context);
        struct tree_node *found_node = tree_search(tree->root, key, &search_context);
        assert(!found_node);
    } else {
        tree_traverse_context_init(&search_context);
        struct tree_node *found_node = tree_search(tree->root, key, &search_context);
        assert(!found_node);
        found_node = tree_search(traverse_context->parent ? traverse_context->parent : tree->root, key, traverse_context);
        assert(!found_node);
        tree_traverse_context_equals(traverse_context, &search_context);
    }

    struct tree_node *node = tree_new_node(NULL, NULL, NULL, true, key_value);
    if (traverse_context)
        traverse_context->parent = node;

    struct tree_node *parent = search_context.parent;
    if (parent) {
        assert(tree->root);
        TREE_NODE_KEY_TYPE parent_key = TREE_NODE_KEY_VALUE_KEY(parent->key_value);
        if (TREE_NODE_KEY_CMP(key, parent_key) < 0) { // key < parent_key
            assert(LEFT(parent) == NULL);
            LEFT_SET(parent, node);
        } else {
            assert(RIGHT(parent) == NULL);
            RIGHT_SET(parent, node);
        }
        PARENT_SET(node, parent);
    } else {
        assert(!tree->root);
        tree->root = node;
    }

    for (;;) {
        if (parent) {
            if (RED(parent)) {
                struct tree_node *grandparent = PARENT(parent), *uncle = NULL;
                if (grandparent) {
                    assert(parent == LEFT(grandparent) || parent == RIGHT(grandparent));
                    uncle = (parent == LEFT(grandparent) ? RIGHT(grandparent) : LEFT(grandparent));
                }
                if (uncle && RED(uncle)) {
                    RED_SET(parent, 0);
                    RED_SET(uncle, 0);
                    RED_SET(grandparent, 1);
                    node = grandparent;
                    parent = PARENT(node);
                } else {
                    assert(grandparent);
                    if (parent == LEFT(grandparent) && node == RIGHT(parent)) {
                        // rotate_left(parent);
                        struct tree_node *save_node = node;
                        LEFT_SET(grandparent, node); PARENT_SET(node, grandparent);
                        RIGHT_SET(parent, LEFT(node)); if (LEFT(node)) PARENT_SET(LEFT(node), parent);
                        LEFT_SET(node, parent); PARENT_SET(parent, node);
                        node = parent;
                        parent = save_node;
                    } else if (node == LEFT(parent) && parent == RIGHT(grandparent)) {
                        // rotate_right(parent);
                        struct tree_node *save_node = node;
                        RIGHT_SET(grandparent, node); PARENT_SET(node, grandparent);
                        LEFT_SET(parent, RIGHT(node)); if (RIGHT(node)) PARENT_SET(RIGHT(node), parent);
                        RIGHT_SET(node, parent); PARENT_SET(parent, node);
                        node = parent;
                        parent = save_node;
                    }
                    assert(RED(parent)); assert(!RED(grandparent));
                    RED_SET(parent, 0);
                    RED_SET(grandparent, 1);
                    struct tree_node *grandgrandparent = PARENT(grandparent);
                    if (node == LEFT(parent) && parent == LEFT(grandparent)) {
                        // rotate_right(grandparent);
                        LEFT_SET(grandparent, RIGHT(parent)); if (RIGHT(parent)) PARENT_SET(RIGHT(parent), grandparent);
                        RIGHT_SET(parent, grandparent); PARENT_SET(grandparent, parent);
                    } else {
                        assert(node == RIGHT(parent) && parent == RIGHT(grandparent));
                        // rotate_left(grandparent);
                        RIGHT_SET(grandparent, LEFT(parent)); if (LEFT(parent)) PARENT_SET(LEFT(parent), grandparent);
                        LEFT_SET(parent, grandparent); PARENT_SET(grandparent, parent);
                    }
                    if (grandgrandparent) {
                        if (grandparent == LEFT(grandgrandparent)) {
                            LEFT_SET(grandgrandparent, parent); PARENT_SET(parent, grandgrandparent);
                        } else {
                            assert(grandparent == RIGHT(grandgrandparent));
                            RIGHT_SET(grandgrandparent, parent); PARENT_SET(parent, grandgrandparent);
                        }
                    } else {
                        tree->root = parent; PARENT_SET(parent, NULL);
                    }
                    break;
                }
            } else {
                break;
            }
        } else {
            RED_SET(node, 0);
            break;
        }
    }

    ++tree->length;
#if TREE_DO_CHECK
    tree_check(tree);
#endif
    TREE_CHECK(tree);
    return NULL;
}

#if TESTS || 1
static int tree_delete(struct tree *tree, TREE_NODE_KEY_TYPE key) {
    struct tree_traverse_context search_context; tree_traverse_context_init(&search_context);
    struct tree_node *node_to_delete = tree_search(tree->root, key, &search_context);
    if (!node_to_delete)
        return 0;

    if (LEFT(node_to_delete) && RIGHT(node_to_delete)) {
        struct tree_node *parent = node_to_delete, *node = LEFT(node_to_delete);
        while (RIGHT(node))
            parent = node, node = RIGHT(node);

        if (tree->root == node_to_delete) {
            tree->root = node;
        } else {
            assert(search_context.parent == PARENT(node_to_delete));
            assert(node_to_delete == LEFT(search_context.parent) || node_to_delete == RIGHT(search_context.parent));
            if (node_to_delete == LEFT(search_context.parent))
                LEFT_SET(search_context.parent, node);
            else
                RIGHT_SET(search_context.parent, node);
        }

        char tmp_buf[offsetof(struct tree_node, key_value)]; _Static_assert(sizeof tmp_buf == 8 * 3);
        memcpy(&tmp_buf, node, sizeof tmp_buf);
        memcpy(node, node_to_delete, sizeof tmp_buf);
        memcpy(node_to_delete, tmp_buf, sizeof tmp_buf);

        if (parent == node_to_delete) {
            assert(node_to_delete == PARENT(node_to_delete));
            parent = node;
        } else {
            assert(parent == PARENT(node_to_delete));
        }
        assert(node == LEFT(parent) || node == RIGHT(parent));
        if (node == LEFT(parent))
            LEFT_SET(parent, node_to_delete);
        else
            RIGHT_SET(parent, node_to_delete);

        if (LEFT(node_to_delete))
            PARENT_SET(LEFT(node_to_delete), node_to_delete);
        if (RIGHT(node_to_delete))
            PARENT_SET(RIGHT(node_to_delete), node_to_delete);
        if (LEFT(node))
            PARENT_SET(LEFT(node), node);
        if (RIGHT(node))
            PARENT_SET(RIGHT(node), node);
#if TREE_DO_CHECK
        tree_check_parameterized(tree, 1);
#endif
    }
#if WRITE_DOT_GRAPH
    tree_write_dot_graph(tree, node_to_delete, PARENT(node_to_delete), NULL, NULL, NULL);
#endif

    TREE_NODE_FREE(node_to_delete);

    struct tree_node *node = LEFT(node_to_delete) ? LEFT(node_to_delete) : RIGHT(node_to_delete); // child
    struct tree_node *parent = PARENT(node_to_delete);
    if (!RED(node_to_delete)) {
        if (!node) { // !child
            if (parent) {
                assert(node_to_delete == LEFT(parent) || node_to_delete == RIGHT(parent));
                struct tree_node *sibling = (node_to_delete == LEFT(parent) ? RIGHT(parent) : LEFT(parent));
                struct tree_node *grandparent, *sibling_child, *sibling_child_child;
                if (node_to_delete == LEFT(parent))
                    LEFT_SET(parent, NULL);
                else
                    RIGHT_SET(parent, NULL);

                for (;;) {
#if WRITE_DOT_GRAPH
                    tree_write_dot_graph(tree, node, parent, PARENT(parent), NULL, sibling);
#endif
                    assert(sibling);
                    if (RED(sibling)) {
                        // case 2
                        assert(!RED(parent));
                        RED_SET(parent, 1);
                        RED_SET(sibling, 0);
                        if (node == LEFT(parent)) {
                            // rotate_left(parent);
                            RIGHT_SET(parent, sibling_child = LEFT(sibling));
                            LEFT_SET(sibling, parent);
                        } else {
                            assert(node == RIGHT(parent));
                            // rotate_right(parent);
                            LEFT_SET(parent, sibling_child = RIGHT(sibling));
                            RIGHT_SET(sibling, parent);
                        }
                        grandparent = PARENT(parent);
                        PARENT_SET(sibling_child, parent);
                        PARENT_SET(sibling, grandparent);
                        PARENT_SET(parent, sibling);
                        if (grandparent) {
                            assert(parent == LEFT(grandparent) || parent == RIGHT(grandparent));
                            if (parent == LEFT(grandparent))
                                LEFT_SET(grandparent, sibling);
                            else
                                RIGHT_SET(grandparent, sibling);
                            PARENT_SET(sibling, grandparent);
                        } else {
                            assert(tree->root == parent);
                            tree->root = sibling;
                            assert(PARENT(sibling) == NULL);
                        }
                        sibling = sibling_child;
                    } else if (!RED(parent) && !(LEFT(sibling) && RED(LEFT(sibling)))
                                            && !(RIGHT(sibling) && RED(RIGHT(sibling)))) {
                        // case 3
                        RED_SET(sibling, 1);
                        node = parent;
                        parent = PARENT(node);
                        if (parent) {
                            sibling = node == LEFT(parent) ? RIGHT(parent) : LEFT(parent);
                            continue;
                        } else
                            goto fin;
                    }
                    break;
                }
#if WRITE_DOT_GRAPH
                tree_write_dot_graph(tree, node, parent, PARENT(parent), NULL, sibling);
#endif
                if (RED(parent) && !RED(sibling) && !(LEFT(sibling) && RED(LEFT(sibling)))
                                                 && !(RIGHT(sibling) && RED(RIGHT(sibling)))) {
                    // case 4
                    RED_SET(sibling, 1);
                    RED_SET(parent, 0);
                } else {
                    assert(!RED(sibling));
                    // case 5
                    if (node == LEFT(parent) && LEFT(sibling) && RED(LEFT(sibling))
                                                       && !(RIGHT(sibling) && RED(RIGHT(sibling)))) {
                        RED_SET(sibling, 1);
                        RED_SET(LEFT(sibling), 0);
                        // rotate_right(sibling);
                        RIGHT_SET(parent, sibling_child = LEFT(sibling)); PARENT_SET(sibling_child, parent);
                        LEFT_SET(sibling, sibling_child_child = RIGHT(sibling_child)); if (sibling_child_child) PARENT_SET(sibling_child_child, sibling);
                        RIGHT_SET(sibling_child, sibling); PARENT_SET(sibling, sibling_child);
                        sibling = sibling_child;
                    } else if (node == RIGHT(parent) && !(LEFT(sibling) && RED(LEFT(sibling)))
                                                               && RIGHT(sibling) && RED(RIGHT(sibling))) {
                        RED_SET(sibling, 1);
                        RED_SET(RIGHT(sibling), 0);
                        // rotate_left(sibling);
                        LEFT_SET(parent, sibling_child = RIGHT(sibling)); PARENT_SET(sibling_child, parent);
                        RIGHT_SET(sibling, sibling_child_child = LEFT(sibling_child)); if (sibling_child_child) PARENT_SET(sibling_child_child, sibling);
                        LEFT_SET(sibling_child, sibling); PARENT_SET(sibling, sibling_child);
                        sibling = sibling_child;
                    }
#if WRITE_DOT_GRAPH
                    tree_write_dot_graph(tree, node, parent, PARENT(parent), NULL, sibling);
#endif
                    assert((LEFT(sibling) && RED(LEFT(sibling))) || (RIGHT(sibling) && RED(RIGHT(sibling))));
                    // case 6
                    RED_SET(sibling, RED(parent));
                    RED_SET(parent, 0);
                    grandparent = PARENT(parent);
                    if (node == LEFT(parent)) {
                        assert(RIGHT(sibling) && RED(RIGHT(sibling)));
                        RED_SET(RIGHT(sibling), 0);
                        // rotate_left(parent);
                        RIGHT_SET(parent, sibling_child = LEFT(sibling)); if (sibling_child) PARENT_SET(sibling_child, parent);
                        LEFT_SET(sibling, parent); PARENT_SET(parent, sibling);
                    } else {
                        assert(node == RIGHT(parent));
                        assert(LEFT(sibling) && RED(LEFT(sibling)));
                        RED_SET(LEFT(sibling), 0);
                        // rotate_right(parent);
                        LEFT_SET(parent, sibling_child = RIGHT(sibling)); if (sibling_child) PARENT_SET(sibling_child, parent);
                        RIGHT_SET(sibling, parent); PARENT_SET(parent, sibling);
                    }
                    if (grandparent) {
                        assert(parent == LEFT(grandparent) || parent == RIGHT(grandparent));
                        if (parent == LEFT(grandparent))
                            LEFT_SET(grandparent, sibling);
                        else
                            RIGHT_SET(grandparent, sibling);
                        PARENT_SET(sibling, grandparent);
                    } else {
                        assert(tree->root == parent);
                        tree->root = sibling; PARENT_SET(sibling, NULL);
                    }
                }
            } else {
                assert(node_to_delete == tree->root && tree->length == 1 && node == NULL);
                tree->root = NULL;
            }
        } else {
            assert(RED(node));
            if (parent) {
                assert(node_to_delete == LEFT(parent) || node_to_delete == RIGHT(parent));
                if (node_to_delete == LEFT(parent))
                    LEFT_SET(parent, node);
                else
                    RIGHT_SET(parent, node);
                PARENT_SET(node, parent);
            } else {
                tree->root = node; PARENT_SET(node, NULL);
            }
            RED_SET(node, 0);
        }
    } else {
        assert(parent);
        assert(node_to_delete == LEFT(parent) || node_to_delete == RIGHT(parent));
        assert(!RED(parent) && (!node || !RED(node)));
        assert(!node);
        if (node_to_delete == LEFT(parent))
            LEFT_SET(parent, NULL);
        else
            RIGHT_SET(parent, NULL);
    }

fin:
    free(node_to_delete);
    --tree->length;
#if TREE_DO_CHECK
    tree_check(tree);
#endif
    TREE_CHECK(tree);
    return true;
}
#endif

static int tree_iterate_parameterized(struct tree *tree, int (*func)(void *data, struct tree_node *), void *data, int no_check) {
    struct tree_node *node = tree->root;
    struct tree_node *stack[100];
    int stack_length = 0;
    int res = 0;
    // https://en.wikipedia.org/wiki/Tree_traversal
    while (node || stack_length > 0) {
        if (node) {
            assert(stack_length < (int)(sizeof stack / sizeof *stack));
            stack[stack_length++] = node;
            assert(no_check || !LEFT(node) || node == PARENT(LEFT(node)));
            assert(no_check || !RIGHT(node) || node == PARENT(RIGHT(node)));
            node = LEFT(node);
        } else {
            node = stack[--stack_length];
            if ((res = func(data, node)) != 0)
                break;
            node = RIGHT(node);
        }
    }
    return res;
}

static int tree_iterate(struct tree *tree, int (*func)(void *data, struct tree_node *), void *data) {
    return tree_iterate_parameterized(tree, func, data, 0);
}
