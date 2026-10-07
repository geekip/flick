#include "flicknet/config.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <yaml.h>

typedef enum {
  FN_YAML_SCALAR = 0,
  FN_YAML_MAPPING,
  FN_YAML_SEQUENCE
} fn_yaml_kind_t;

typedef struct fn_yaml_node fn_yaml_node_t;

struct fn_yaml_node {
  fn_yaml_kind_t kind;
  char *scalar;
  size_t scalar_length;
  yaml_scalar_style_t scalar_style;
  size_t line;
  size_t column;
  fn_yaml_node_t *first;
  fn_yaml_node_t *last;
  fn_yaml_node_t *next;
};

typedef struct {
  yaml_parser_t parser;
  fn_allocator_t allocator;
  size_t node_count;
  fn_config_error_t *error;
} fn_yaml_context_t;

static fn_result_t config_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_CONFIG,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static void clear_error(fn_config_error_t *error)
{
  if (error != NULL) {
    memset(error, 0, sizeof(*error));
  }
}

static void set_error(fn_config_error_t *error, fn_config_error_code_t code,
                      const char *path, const fn_yaml_node_t *node,
                      const char *message)
{
  if (error == NULL || error->code != FN_CONFIG_ERROR_NONE) {
    return;
  }
  error->code = code;
  if (path != NULL) {
    (void)snprintf(error->path, sizeof(error->path), "%s", path);
  }
  if (node != NULL) {
    error->line = node->line;
    error->column = node->column;
    error->has_mark = true;
  }
  if (message != NULL) {
    (void)snprintf(error->message, sizeof(error->message), "%s", message);
  }
}

static void set_parser_error(fn_yaml_context_t *context)
{
  fn_config_error_code_t code = FN_CONFIG_ERROR_YAML_SYNTAX;
  fn_config_error_t *error = context->error;
  if (error == NULL || error->code != FN_CONFIG_ERROR_NONE) {
    return;
  }
  if (context->parser.error == YAML_READER_ERROR) {
    code = FN_CONFIG_ERROR_UTF8;
  }
  error->code = code;
  error->line = context->parser.problem_mark.line + 1u;
  error->column = context->parser.problem_mark.column + 1u;
  error->has_mark = true;
  (void)snprintf(error->message, sizeof(error->message), "%s",
                 context->parser.problem != NULL ?
                 context->parser.problem : "Invalid YAML input.");
}

static void *allocate_zero(fn_allocator_t allocator, size_t size)
{
  void *pointer = allocator.allocate(allocator.context, size);
  if (pointer != NULL) {
    memset(pointer, 0, size);
  }
  return pointer;
}

static fn_yaml_node_t *yaml_node_new(fn_yaml_context_t *context,
                                     fn_yaml_kind_t kind,
                                     const yaml_mark_t *mark)
{
  fn_yaml_node_t *node;
  if (context->node_count >= FN_CONFIG_MAX_NODES) {
    set_error(context->error, FN_CONFIG_ERROR_YAML_LIMIT, "", NULL,
              "YAML node limit exceeded.");
    return NULL;
  }
  node = allocate_zero(context->allocator, sizeof(*node));
  if (node == NULL) {
    set_error(context->error, FN_CONFIG_ERROR_NO_MEMORY, "", NULL,
              "Configuration allocation failed.");
    return NULL;
  }
  context->node_count++;
  node->kind = kind;
  node->line = mark->line + 1u;
  node->column = mark->column + 1u;
  return node;
}

static void yaml_node_destroy(fn_allocator_t allocator, fn_yaml_node_t *node)
{
  fn_yaml_node_t *child;
  while (node != NULL) {
    fn_yaml_node_t *next = node->next;
    child = node->first;
    yaml_node_destroy(allocator, child);
    if (node->scalar != NULL) {
      allocator.deallocate(allocator.context, node->scalar);
    }
    allocator.deallocate(allocator.context, node);
    node = next;
  }
}

static bool yaml_tag_allowed(const yaml_char_t *tag)
{
  static const char standard_prefix[] = "tag:yaml.org,2002:";
  if (tag == NULL) {
    return true;
  }
  return strncmp((const char *)tag, standard_prefix,
                 sizeof(standard_prefix) - 1u) == 0;
}

static bool yaml_next(fn_yaml_context_t *context, yaml_event_t *event)
{
  memset(event, 0, sizeof(*event));
  if (!yaml_parser_parse(&context->parser, event)) {
    set_parser_error(context);
    return false;
  }
  return true;
}

static bool yaml_event_forbidden(const yaml_event_t *event)
{
  switch (event->type) {
    case YAML_ALIAS_EVENT:
      return true;
    case YAML_SCALAR_EVENT:
      return event->data.scalar.anchor != NULL ||
             !yaml_tag_allowed(event->data.scalar.tag);
    case YAML_SEQUENCE_START_EVENT:
      return event->data.sequence_start.anchor != NULL ||
             !yaml_tag_allowed(event->data.sequence_start.tag);
    case YAML_MAPPING_START_EVENT:
      return event->data.mapping_start.anchor != NULL ||
             !yaml_tag_allowed(event->data.mapping_start.tag);
    default:
      return false;
  }
}

static void yaml_append(fn_yaml_node_t *parent, fn_yaml_node_t *child)
{
  if (parent->last == NULL) {
    parent->first = child;
  } else {
    parent->last->next = child;
  }
  parent->last = child;
}

static bool yaml_parse_node(fn_yaml_context_t *context, yaml_event_t *event,
                            size_t depth, fn_yaml_node_t **out)
{
  fn_yaml_node_t *node = NULL;
  yaml_event_t child_event;

  *out = NULL;
  if (depth > FN_CONFIG_MAX_DEPTH) {
    set_error(context->error, FN_CONFIG_ERROR_YAML_LIMIT, "", NULL,
              "YAML nesting depth exceeded.");
    yaml_event_delete(event);
    return false;
  }
  if (yaml_event_forbidden(event)) {
    set_error(context->error, FN_CONFIG_ERROR_YAML_UNSUPPORTED, "", NULL,
              "YAML aliases, anchors or custom tags are not supported.");
    yaml_event_delete(event);
    return false;
  }

  if (event->type == YAML_SCALAR_EVENT) {
    size_t allocation_size;
    node = yaml_node_new(context, FN_YAML_SCALAR, &event->start_mark);
    if (node == NULL) {
      yaml_event_delete(event);
      return false;
    }
    if (event->data.scalar.length > FN_CONFIG_MAX_SCALAR ||
        !fn_size_add(event->data.scalar.length, (size_t)1u,
                     &allocation_size)) {
      set_error(context->error, FN_CONFIG_ERROR_YAML_LIMIT, "", node,
                "YAML scalar limit exceeded.");
      yaml_event_delete(event);
      yaml_node_destroy(context->allocator, node);
      return false;
    }
    node->scalar = context->allocator.allocate(context->allocator.context,
                                                allocation_size);
    if (node->scalar == NULL) {
      set_error(context->error, FN_CONFIG_ERROR_NO_MEMORY, "", node,
                "Configuration allocation failed.");
      yaml_event_delete(event);
      yaml_node_destroy(context->allocator, node);
      return false;
    }
    memcpy(node->scalar, event->data.scalar.value,
           event->data.scalar.length);
    node->scalar[event->data.scalar.length] = '\0';
    node->scalar_length = event->data.scalar.length;
    node->scalar_style = event->data.scalar.style;
    yaml_event_delete(event);
    *out = node;
    return true;
  }

  if (event->type != YAML_MAPPING_START_EVENT &&
      event->type != YAML_SEQUENCE_START_EVENT) {
    set_error(context->error, FN_CONFIG_ERROR_YAML_SYNTAX, "", NULL,
              "Unexpected YAML event.");
    yaml_event_delete(event);
    return false;
  }
  node = yaml_node_new(context,
                       event->type == YAML_MAPPING_START_EVENT ?
                       FN_YAML_MAPPING : FN_YAML_SEQUENCE,
                       &event->start_mark);
  yaml_event_delete(event);
  if (node == NULL) {
    return false;
  }

  for (;;) {
    fn_yaml_node_t *child = NULL;
    if (!yaml_next(context, &child_event)) {
      yaml_node_destroy(context->allocator, node);
      return false;
    }
    if ((node->kind == FN_YAML_MAPPING &&
         child_event.type == YAML_MAPPING_END_EVENT) ||
        (node->kind == FN_YAML_SEQUENCE &&
         child_event.type == YAML_SEQUENCE_END_EVENT)) {
      yaml_event_delete(&child_event);
      break;
    }
    if (!yaml_parse_node(context, &child_event, depth + 1u, &child)) {
      yaml_node_destroy(context->allocator, node);
      return false;
    }
    yaml_append(node, child);
  }
  *out = node;
  return true;
}

static bool yaml_parse_document(const uint8_t *input, size_t input_length,
                                fn_allocator_t allocator,
                                fn_yaml_node_t **out,
                                fn_config_error_t *error)
{
  fn_yaml_context_t context;
  yaml_event_t event;
  bool parser_initialized = false;
  bool success = false;

  *out = NULL;
  memset(&context, 0, sizeof(context));
  context.allocator = allocator;
  context.error = error;
  if (!yaml_parser_initialize(&context.parser)) {
    set_error(error, FN_CONFIG_ERROR_NO_MEMORY, "", NULL,
              "YAML parser initialization failed.");
    return false;
  }
  parser_initialized = true;
  yaml_parser_set_input_string(&context.parser, input, input_length);

  if (!yaml_next(&context, &event) || event.type != YAML_STREAM_START_EVENT) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_YAML_SYNTAX, "", NULL,
                "YAML stream start is missing.");
    }
    if (event.type != YAML_NO_EVENT) {
      yaml_event_delete(&event);
    }
    goto done;
  }
  yaml_event_delete(&event);
  if (!yaml_next(&context, &event) || event.type != YAML_DOCUMENT_START_EVENT) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_YAML_SYNTAX, "", NULL,
                "YAML document start is missing.");
    }
    if (event.type != YAML_NO_EVENT) {
      yaml_event_delete(&event);
    }
    goto done;
  }
  yaml_event_delete(&event);
  if (!yaml_next(&context, &event) ||
      !yaml_parse_node(&context, &event, (size_t)1u, out)) {
    goto done;
  }
  if (!yaml_next(&context, &event) || event.type != YAML_DOCUMENT_END_EVENT) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_YAML_SYNTAX, "", NULL,
                "YAML document end is missing.");
    }
    if (event.type != YAML_NO_EVENT) {
      yaml_event_delete(&event);
    }
    goto done;
  }
  yaml_event_delete(&event);
  if (!yaml_next(&context, &event) || event.type != YAML_STREAM_END_EVENT) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_YAML_UNSUPPORTED, "", NULL,
                "Multiple YAML documents are not supported.");
    }
    if (event.type != YAML_NO_EVENT) {
      yaml_event_delete(&event);
    }
    goto done;
  }
  yaml_event_delete(&event);
  success = true;

done:
  if (!success && *out != NULL) {
    yaml_node_destroy(allocator, *out);
    *out = NULL;
  }
  if (parser_initialized) {
    yaml_parser_delete(&context.parser);
  }
  return success;
}

static bool node_is_null(const fn_yaml_node_t *node)
{
  if (node == NULL || node->kind != FN_YAML_SCALAR ||
      node->scalar_style != YAML_PLAIN_SCALAR_STYLE) {
    return false;
  }
  return node->scalar_length == 0 || strcmp(node->scalar, "null") == 0 ||
         strcmp(node->scalar, "Null") == 0 ||
         strcmp(node->scalar, "NULL") == 0 || strcmp(node->scalar, "~") == 0;
}

static void path_join(char out[FN_CONFIG_PATH_MAX], const char *parent,
                      const char *child)
{
  if (parent == NULL || parent[0] == '\0') {
    (void)snprintf(out, FN_CONFIG_PATH_MAX, "%s", child);
  } else {
    (void)snprintf(out, FN_CONFIG_PATH_MAX, "%s.%s", parent, child);
  }
}

static void path_index(char out[FN_CONFIG_PATH_MAX], const char *parent,
                       size_t index)
{
  (void)snprintf(out, FN_CONFIG_PATH_MAX, "%s[%zu]", parent, index);
}

static bool validate_duplicate_keys(const fn_yaml_node_t *node,
                                    const char *path,
                                    fn_config_error_t *error)
{
  const fn_yaml_node_t *child;
  size_t index = 0;
  if (node->kind == FN_YAML_MAPPING) {
    for (child = node->first; child != NULL; ) {
      const fn_yaml_node_t *key = child;
      const fn_yaml_node_t *value = child->next;
      const fn_yaml_node_t *prior;
      char child_path[FN_CONFIG_PATH_MAX];
      if (key->kind != FN_YAML_SCALAR || value == NULL) {
        set_error(error, FN_CONFIG_ERROR_TYPE, path, key,
                  "Mapping keys must be scalar strings.");
        return false;
      }
      path_join(child_path, path, key->scalar);
      if (strcmp(key->scalar, "<<") == 0) {
        set_error(error, FN_CONFIG_ERROR_YAML_UNSUPPORTED, child_path, key,
                  "YAML merge keys are not supported.");
        return false;
      }
      for (prior = node->first; prior != key; prior = prior->next->next) {
        if (prior->scalar_length == key->scalar_length &&
            memcmp(prior->scalar, key->scalar, key->scalar_length) == 0) {
          set_error(error, FN_CONFIG_ERROR_DUPLICATE_KEY, child_path, key,
                    "Duplicate mapping key.");
          return false;
        }
      }
      if (!validate_duplicate_keys(value, child_path, error)) {
        return false;
      }
      child = value->next;
    }
  } else if (node->kind == FN_YAML_SEQUENCE) {
    for (child = node->first; child != NULL; child = child->next) {
      char child_path[FN_CONFIG_PATH_MAX];
      path_index(child_path, path, index++);
      if (!validate_duplicate_keys(child, child_path, error)) {
        return false;
      }
    }
  }
  return true;
}

static const fn_yaml_node_t *mapping_get(const fn_yaml_node_t *mapping,
                                         const char *key)
{
  const fn_yaml_node_t *child;
  if (mapping == NULL || mapping->kind != FN_YAML_MAPPING) {
    return NULL;
  }
  for (child = mapping->first; child != NULL && child->next != NULL;
       child = child->next->next) {
    if (strcmp(child->scalar, key) == 0) {
      return child->next;
    }
  }
  return NULL;
}

static bool name_in_list(const char *name, const char *const *allowed,
                         size_t allowed_count)
{
  size_t index;
  for (index = 0; index < allowed_count; index++) {
    if (strcmp(name, allowed[index]) == 0) {
      return true;
    }
  }
  return false;
}

static bool validate_allowed_fields(const fn_yaml_node_t *mapping,
                                    const char *path,
                                    const char *const *allowed,
                                    size_t allowed_count,
                                    fn_config_error_t *error)
{
  const fn_yaml_node_t *child;
  if (mapping == NULL || mapping->kind != FN_YAML_MAPPING) {
    set_error(error, FN_CONFIG_ERROR_TYPE, path, mapping,
              "Expected a mapping.");
    return false;
  }
  for (child = mapping->first; child != NULL; child = child->next->next) {
    char child_path[FN_CONFIG_PATH_MAX];
    if (!name_in_list(child->scalar, allowed, allowed_count)) {
      path_join(child_path, path, child->scalar);
      set_error(error, FN_CONFIG_ERROR_UNKNOWN_FIELD, child_path, child,
                "Unknown configuration field.");
      return false;
    }
  }
  return true;
}

static bool require_scalar(const fn_yaml_node_t *node, const char *path,
                           fn_config_error_t *error)
{
  if (node_is_null(node)) {
    set_error(error, FN_CONFIG_ERROR_NULL, path, node,
              "Null is not allowed for this field.");
    return false;
  }
  if (node == NULL || node->kind != FN_YAML_SCALAR) {
    set_error(error, FN_CONFIG_ERROR_TYPE, path, node,
              "Expected a scalar value.");
    return false;
  }
  return true;
}

static bool parse_u64(const fn_yaml_node_t *node, const char *path,
                      uint64_t *out, fn_config_error_t *error)
{
  uint64_t value = 0;
  size_t index;
  if (!require_scalar(node, path, error)) {
    return false;
  }
  if (node->scalar_length == 0) {
    set_error(error, FN_CONFIG_ERROR_TYPE, path, node,
              "Expected an unsigned decimal integer.");
    return false;
  }
  for (index = 0; index < node->scalar_length; index++) {
    const unsigned char character = (unsigned char)node->scalar[index];
    const uint64_t digit = (uint64_t)(character - (unsigned char)'0');
    if (character < (unsigned char)'0' || character > (unsigned char)'9') {
      set_error(error, FN_CONFIG_ERROR_TYPE, path, node,
                "Expected an unsigned decimal integer.");
      return false;
    }
    if (value > (UINT64_MAX - digit) / UINT64_C(10)) {
      set_error(error, FN_CONFIG_ERROR_OVERFLOW, path, node,
                "Integer value is not representable.");
      return false;
    }
    value = value * UINT64_C(10) + digit;
  }
  *out = value;
  return true;
}

static bool parse_bool(const fn_yaml_node_t *node, const char *path,
                       bool *out, fn_config_error_t *error)
{
  if (!require_scalar(node, path, error)) {
    return false;
  }
  if (strcmp(node->scalar, "true") == 0) {
    *out = true;
    return true;
  }
  if (strcmp(node->scalar, "false") == 0) {
    *out = false;
    return true;
  }
  set_error(error, FN_CONFIG_ERROR_TYPE, path, node,
            "Expected literal true or false.");
  return false;
}

static bool parse_scaled(const fn_yaml_node_t *node, const char *path,
                         const char *const *suffixes,
                         const uint64_t *multipliers, size_t suffix_count,
                         uint64_t *out, fn_config_error_t *error)
{
  size_t suffix_index;
  size_t number_length = 0;
  uint64_t value = 0;
  if (!require_scalar(node, path, error)) {
    return false;
  }
  for (suffix_index = 0; suffix_index < suffix_count; suffix_index++) {
    const size_t suffix_length = strlen(suffixes[suffix_index]);
    if (node->scalar_length > suffix_length &&
        memcmp(node->scalar + node->scalar_length - suffix_length,
               suffixes[suffix_index], suffix_length) == 0) {
      number_length = node->scalar_length - suffix_length;
      break;
    }
  }
  if (suffix_index == suffix_count || number_length == 0) {
    set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
              "Value has an unsupported unit.");
    return false;
  }
  {
    size_t index;
    for (index = 0; index < number_length; index++) {
      const unsigned char character = (unsigned char)node->scalar[index];
      const uint64_t digit = (uint64_t)(character - (unsigned char)'0');
      if (character < (unsigned char)'0' || character > (unsigned char)'9') {
        set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
                  "Value must start with an unsigned decimal integer.");
        return false;
      }
      if (value > (UINT64_MAX - digit) / UINT64_C(10)) {
        set_error(error, FN_CONFIG_ERROR_OVERFLOW, path, node,
                  "Scaled value is not representable.");
        return false;
      }
      value = value * UINT64_C(10) + digit;
    }
  }
  if (multipliers[suffix_index] != 0 &&
      value > UINT64_MAX / multipliers[suffix_index]) {
    set_error(error, FN_CONFIG_ERROR_OVERFLOW, path, node,
              "Scaled value is not representable.");
    return false;
  }
  *out = value * multipliers[suffix_index];
  return true;
}

static bool parse_bytes(const fn_yaml_node_t *node, const char *path,
                        size_t *out, fn_config_error_t *error)
{
  static const char *const suffixes[] = {"MiB", "KiB", "B"};
  static const uint64_t multipliers[] = {
    UINT64_C(1048576), UINT64_C(1024), UINT64_C(1),
  };
  uint64_t value;
  if (!parse_scaled(node, path, suffixes, multipliers,
                    sizeof(suffixes) / sizeof(suffixes[0]),
                    &value, error)) {
    return false;
  }
  if (value > (uint64_t)SIZE_MAX) {
    set_error(error, FN_CONFIG_ERROR_OVERFLOW, path, node,
              "Byte value exceeds platform size_t.");
    return false;
  }
  *out = (size_t)value;
  return true;
}

static bool parse_duration(const fn_yaml_node_t *node, const char *path,
                           uint64_t *out, fn_config_error_t *error)
{
  static const char *const suffixes[] = {"ms", "s", "m", "h"};
  static const uint64_t multipliers[] = {
    UINT64_C(1), UINT64_C(1000), UINT64_C(60000), UINT64_C(3600000),
  };
  return parse_scaled(node, path, suffixes, multipliers,
                      sizeof(suffixes) / sizeof(suffixes[0]), out, error);
}

static bool scalar_equal(const fn_yaml_node_t *node, const char *value)
{
  return node != NULL && node->kind == FN_YAML_SCALAR &&
         strcmp(node->scalar, value) == 0;
}

static bool valid_object_name(const fn_yaml_node_t *node, const char *path,
                              char out[FN_CONFIG_NAME_MAX + 1u],
                              fn_config_error_t *error)
{
  size_t index;
  if (!require_scalar(node, path, error)) {
    return false;
  }
  if (node->scalar_length == 0 || node->scalar_length > FN_CONFIG_NAME_MAX) {
    set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
              "Object name length is outside 1..64 bytes.");
    return false;
  }
  for (index = 0; index < node->scalar_length; index++) {
    const unsigned char value = (unsigned char)node->scalar[index];
    if (!((value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
          (value >= (unsigned char)'a' && value <= (unsigned char)'z') ||
          (value >= (unsigned char)'0' && value <= (unsigned char)'9') ||
          value == (unsigned char)'.' || value == (unsigned char)'_' ||
          value == (unsigned char)'-')) {
      set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
                "Object name contains an unsupported character.");
      return false;
    }
  }
  memcpy(out, node->scalar, node->scalar_length + 1u);
  return true;
}

static size_t sequence_count(const fn_yaml_node_t *sequence)
{
  const fn_yaml_node_t *child;
  size_t count = 0;
  for (child = sequence->first; child != NULL; child = child->next) {
    count++;
  }
  return count;
}

static bool parse_port(const fn_yaml_node_t *node, const char *path,
                       uint16_t *out, fn_config_error_t *error)
{
  uint64_t value;
  if (!parse_u64(node, path, &value, error)) {
    return false;
  }
  if (value == 0 || value > UINT16_MAX) {
    set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
              "Port is outside 1..65535.");
    return false;
  }
  *out = (uint16_t)value;
  return true;
}

static bool parse_ipv4(const fn_yaml_node_t *node, const char *path,
                       fn_addr_t *out, fn_config_error_t *error)
{
  uint8_t bytes[4];
  if (!require_scalar(node, path, error)) {
    return false;
  }
  if (inet_pton(AF_INET, node->scalar, bytes) != 1 ||
      fn_addr_from_v4(out, bytes).code != FN_OK) {
    set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
              "Expected a numeric IPv4 address.");
    return false;
  }
  return true;
}

static bool parse_server(const fn_yaml_node_t *node, const char *path,
                         fn_addr_t *out, fn_config_error_t *error)
{
  uint8_t bytes[4];
  fn_domain_t domain;
  if (!require_scalar(node, path, error)) {
    return false;
  }
  if (inet_pton(AF_INET, node->scalar, bytes) == 1) {
    return fn_addr_from_v4(out, bytes).code == FN_OK;
  }
  if (fn_domain_from_bytes(&domain, (const uint8_t *)node->scalar,
                           node->scalar_length).code != FN_OK ||
      fn_addr_from_domain(out, &domain).code != FN_OK) {
    set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
              "Expected a numeric IPv4 address or ASCII domain.");
    return false;
  }
  return true;
}

static bool copy_secret(const fn_yaml_node_t *node, const char *path,
                        char out[256], uint8_t *out_length,
                        fn_config_error_t *error)
{
  if (!require_scalar(node, path, error)) {
    return false;
  }
  if (node->scalar_length == 0 || node->scalar_length > 255u) {
    set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
              "Secret length is outside 1..255 bytes.");
    return false;
  }
  memcpy(out, node->scalar, node->scalar_length);
  out[node->scalar_length] = '\0';
  *out_length = (uint8_t)node->scalar_length;
  return true;
}

static bool allocate_array(fn_config_t *config, size_t count,
                           size_t item_size, void **out,
                           fn_config_error_t *error)
{
  size_t bytes;
  *out = NULL;
  if (count == 0) {
    return true;
  }
  if (!fn_size_multiply(count, item_size, &bytes)) {
    set_error(error, FN_CONFIG_ERROR_OVERFLOW, "", NULL,
              "Configuration allocation size overflowed.");
    return false;
  }
  *out = allocate_zero(config->allocator, bytes);
  if (*out == NULL) {
    set_error(error, FN_CONFIG_ERROR_NO_MEMORY, "", NULL,
              "Configuration allocation failed.");
    return false;
  }
  return true;
}

static bool parse_limits(const fn_yaml_node_t *mapping, fn_config_t *config,
                         fn_config_error_t *error)
{
  static const char *const allowed[] = {
    "sessions", "handshakes", "fds", "memory", "cleanup-reserve",
    "buffers", "async-operations", "workers", "worker-jobs",
    "lazy-waiters", "lazy-waiters-per-object", "resource-waiters",
    "resolver-pending", "retired-runtimes",
  };
  const struct {
    const char *name;
    size_t *target;
    uint64_t minimum;
    uint64_t maximum;
  } integers[] = {
    {"sessions", &config->limits.session_limit, UINT64_C(1), UINT64_C(1000000)},
    {"handshakes", &config->limits.handshake_limit, UINT64_C(1), UINT64_C(1000000)},
    {"fds", &config->limits.fd_limit, UINT64_C(64), UINT64_C(1000000)},
    {"async-operations", &config->limits.async_operation_limit,
     UINT64_C(64), UINT64_C(1000000)},
    {"workers", &config->limits.worker_limit, UINT64_C(1), UINT64_C(16)},
    {"worker-jobs", &config->limits.worker_job_limit,
     UINT64_C(1), UINT64_C(4096)},
    {"lazy-waiters", &config->limits.lazy_waiter_limit,
     UINT64_C(1), UINT64_C(65536)},
    {"lazy-waiters-per-object", &config->limits.lazy_waiter_per_object_limit,
     UINT64_C(1), UINT64_C(65536)},
    {"resource-waiters", &config->limits.resource_waiter_limit,
     UINT64_C(1), UINT64_C(65536)},
    {"resolver-pending", &config->limits.resolver_pending_limit,
     UINT64_C(1), UINT64_C(4096)},
    {"retired-runtimes", &config->limits.retired_runtime_limit,
     UINT64_C(1), UINT64_C(8)},
  };
  size_t index;
  const fn_yaml_node_t *node;

  if (!validate_allowed_fields(mapping, "limits", allowed,
                               sizeof(allowed) / sizeof(allowed[0]), error)) {
    return false;
  }
  for (index = 0; index < sizeof(integers) / sizeof(integers[0]); index++) {
    uint64_t value;
    char path[FN_CONFIG_PATH_MAX];
    node = mapping_get(mapping, integers[index].name);
    if (node == NULL) {
      continue;
    }
    path_join(path, "limits", integers[index].name);
    if (!parse_u64(node, path, &value, error)) {
      return false;
    }
    if (value < integers[index].minimum || value > integers[index].maximum ||
        value > (uint64_t)SIZE_MAX) {
      set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
                "Resource limit is outside the supported range.");
      return false;
    }
    *integers[index].target = (size_t)value;
  }

  node = mapping_get(mapping, "memory");
  if (node != NULL &&
      !parse_bytes(node, "limits.memory",
                   &config->limits.owned_memory_limit_bytes, error)) {
    return false;
  }
  node = mapping_get(mapping, "cleanup-reserve");
  if (node != NULL &&
      !parse_bytes(node, "limits.cleanup-reserve",
                   &config->limits.cleanup_reserve_bytes, error)) {
    return false;
  }
  node = mapping_get(mapping, "buffers");
  if (node != NULL &&
      !parse_bytes(node, "limits.buffers",
                   &config->limits.buffer_pool_limit_bytes, error)) {
    return false;
  }

  if (config->limits.async_operation_limit > SIZE_MAX / (size_t)256u) {
    set_error(error, FN_CONFIG_ERROR_OVERFLOW, "limits.async-operations",
              mapping_get(mapping, "async-operations"),
              "Derived completion budget overflows size_t.");
    return false;
  }
  config->limits.completion_entry_limit =
    config->limits.async_operation_limit;
  config->limits.completion_limit_bytes =
    config->limits.async_operation_limit * (size_t)256u;

  if (config->limits.handshake_limit > config->limits.session_limit) {
    set_error(error, FN_CONFIG_ERROR_RANGE, "limits.handshakes",
              mapping_get(mapping, "handshakes"),
              "Handshake limit exceeds session limit.");
    return false;
  }
  if (config->limits.worker_job_limit < config->limits.worker_limit) {
    set_error(error, FN_CONFIG_ERROR_RANGE, "limits.worker-jobs",
              mapping_get(mapping, "worker-jobs"),
              "Worker job limit is below worker count.");
    return false;
  }
  if (config->limits.lazy_waiter_per_object_limit >
      config->limits.lazy_waiter_limit) {
    set_error(error, FN_CONFIG_ERROR_RANGE, "limits.lazy-waiters-per-object",
              mapping_get(mapping, "lazy-waiters-per-object"),
              "Per-object lazy waiter limit exceeds the global limit.");
    return false;
  }
  if (config->limits.owned_memory_limit_bytes <
      (size_t)8u * 1024u * 1024u) {
    set_error(error, FN_CONFIG_ERROR_RANGE, "limits.memory",
              mapping_get(mapping, "memory"),
              "Owned memory limit is below 8 MiB.");
    return false;
  }
  {
    size_t cleanup_max = config->limits.owned_memory_limit_bytes / 4u;
    const size_t absolute_max = (size_t)16u * 1024u * 1024u;
    if (cleanup_max > absolute_max) {
      cleanup_max = absolute_max;
    }
    if (config->limits.cleanup_reserve_bytes <
          (size_t)256u * 1024u ||
        config->limits.cleanup_reserve_bytes > cleanup_max) {
      set_error(error, FN_CONFIG_ERROR_RANGE, "limits.cleanup-reserve",
                mapping_get(mapping, "cleanup-reserve"),
                "Cleanup reserve is outside the supported range.");
      return false;
    }
  }
  if (config->limits.buffer_pool_limit_bytes < (size_t)64u * 1024u ||
      config->limits.buffer_pool_limit_bytes >=
        config->limits.owned_memory_limit_bytes -
        config->limits.cleanup_reserve_bytes) {
    set_error(error, FN_CONFIG_ERROR_RANGE, "limits.buffers",
              mapping_get(mapping, "buffers"),
              "Buffer budget is outside the supported range.");
    return false;
  }
  return true;
}

static bool parse_timeouts(const fn_yaml_node_t *mapping, fn_config_t *config,
                           fn_config_error_t *error)
{
  static const char *const allowed[] = {
    "handshake", "connect", "tcp-idle", "drain", "resource-wait",
    "worker-task",
  };
  const struct {
    const char *name;
    uint64_t *target;
  } fields[] = {
    {"handshake", &config->timeouts.handshake_ms},
    {"connect", &config->timeouts.connect_ms},
    {"tcp-idle", &config->timeouts.tcp_idle_ms},
    {"drain", &config->timeouts.drain_ms},
    {"resource-wait", &config->timeouts.resource_wait_ms},
    {"worker-task", &config->timeouts.worker_task_ms},
  };
  size_t index;
  if (!validate_allowed_fields(mapping, "timeouts", allowed,
                               sizeof(allowed) / sizeof(allowed[0]), error)) {
    return false;
  }
  for (index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    const fn_yaml_node_t *node = mapping_get(mapping, fields[index].name);
    char path[FN_CONFIG_PATH_MAX];
    if (node == NULL) {
      continue;
    }
    path_join(path, "timeouts", fields[index].name);
    if (!parse_duration(node, path, fields[index].target, error)) {
      return false;
    }
    if (*fields[index].target < UINT64_C(1) ||
        *fields[index].target > UINT64_C(86400000)) {
      set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
                "Timeout is outside 1ms..24h.");
      return false;
    }
  }
  config->limits.resource_wait_timeout_ms = config->timeouts.resource_wait_ms;
  config->limits.worker_task_timeout_ms = config->timeouts.worker_task_ms;
  return true;
}

static bool parse_users(const fn_yaml_node_t *mapping, const char *path,
                        fn_config_t *config, fn_inbound_config_t *inbound,
                        fn_config_error_t *error)
{
  const fn_yaml_node_t *child;
  size_t index = 0;
  if (mapping == NULL) {
    return true;
  }
  if (mapping->kind != FN_YAML_MAPPING) {
    set_error(error, FN_CONFIG_ERROR_TYPE, path, mapping,
              "Expected a username/password mapping.");
    return false;
  }
  inbound->user_count = sequence_count(mapping) / 2u;
  if (inbound->user_count > 1024u) {
    set_error(error, FN_CONFIG_ERROR_COLLECTION_LIMIT, path, mapping,
              "User collection limit exceeded.");
    return false;
  }
  if (!allocate_array(config, inbound->user_count,
                      sizeof(*inbound->users), (void **)&inbound->users,
                      error)) {
    return false;
  }
  for (child = mapping->first; child != NULL; child = child->next->next) {
    const fn_yaml_node_t *value = child->next;
    char user_path[FN_CONFIG_PATH_MAX];
    size_t path_length = strlen(path);
    if (path_length >= sizeof(user_path)) {
      path_length = sizeof(user_path) - 1u;
    }
    memcpy(user_path, path, path_length);
    user_path[path_length] = '\0';
    if (!copy_secret(child, user_path,
                     inbound->users[index].username,
                     &inbound->users[index].username_length, error) ||
        !copy_secret(value, user_path,
                     inbound->users[index].password,
                     &inbound->users[index].password_length, error)) {
      return false;
    }
    index++;
  }
  return true;
}

static bool parse_inbounds(const fn_yaml_node_t *sequence,
                           fn_config_t *config, fn_config_error_t *error)
{
  static const char *const allowed[] = {
    "name", "type", "listen", "port", "udp", "users",
  };
  const fn_yaml_node_t *item;
  size_t index = 0;
  if (sequence == NULL) {
    set_error(error, FN_CONFIG_ERROR_REQUIRED, "inbounds", NULL,
              "At least one inbound is required.");
    return false;
  }
  if (sequence->kind != FN_YAML_SEQUENCE) {
    set_error(error, FN_CONFIG_ERROR_TYPE, "inbounds", sequence,
              "Expected an inbound sequence.");
    return false;
  }
  config->inbound_count = sequence_count(sequence);
  if (config->inbound_count == 0 || config->inbound_count > 256u) {
    set_error(error, config->inbound_count == 0 ? FN_CONFIG_ERROR_RANGE :
              FN_CONFIG_ERROR_COLLECTION_LIMIT, "inbounds", sequence,
              "Inbound collection is empty or too large.");
    return false;
  }
  if (!allocate_array(config, config->inbound_count,
                      sizeof(*config->inbounds), (void **)&config->inbounds,
                      error)) {
    return false;
  }
  for (item = sequence->first; item != NULL; item = item->next, index++) {
    fn_inbound_config_t *inbound = &config->inbounds[index];
    const fn_yaml_node_t *node;
    uint8_t loopback[4] = {UINT8_C(127), UINT8_C(0), UINT8_C(0), UINT8_C(1)};
    char base[FN_CONFIG_PATH_MAX];
    char path[FN_CONFIG_PATH_MAX];
    size_t prior;
    path_index(base, "inbounds", index);
    if (!validate_allowed_fields(item, base, allowed,
                                 sizeof(allowed) / sizeof(allowed[0]), error)) {
      return false;
    }
    node = mapping_get(item, "name");
    path_join(path, base, "name");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Inbound name is required.");
      return false;
    }
    if (!valid_object_name(node, path, inbound->name, error)) {
      return false;
    }
    for (prior = 0; prior < index; prior++) {
      if (strcmp(config->inbounds[prior].name, inbound->name) == 0) {
        set_error(error, FN_CONFIG_ERROR_DUPLICATE_NAME, path, node,
                  "Inbound name is duplicated.");
        return false;
      }
    }
    node = mapping_get(item, "type");
    path_join(path, base, "type");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Inbound type is required.");
      return false;
    }
    if (!require_scalar(node, path, error)) {
      return false;
    }
    if (!scalar_equal(node, "socks5")) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, path, node,
                "Inbound type is not supported by V0.1.");
      return false;
    }
    node = mapping_get(item, "listen");
    path_join(path, base, "listen");
    if (node == NULL) {
      if (fn_addr_from_v4(&inbound->listen, loopback).code != FN_OK) {
        return false;
      }
    } else if (!parse_ipv4(node, path, &inbound->listen, error)) {
      return false;
    }
    node = mapping_get(item, "port");
    path_join(path, base, "port");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Inbound port is required.");
      return false;
    }
    if (!parse_port(node, path, &inbound->port, error)) {
      return false;
    }
    node = mapping_get(item, "udp");
    path_join(path, base, "udp");
    if (node != NULL && !parse_bool(node, path, &inbound->udp, error)) {
      return false;
    }
    if (inbound->udp) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, path, node,
                "SOCKS UDP is not supported by V0.1.");
      return false;
    }
    path_join(path, base, "users");
    if (!parse_users(mapping_get(item, "users"), path, config, inbound,
                     error)) {
      return false;
    }
    for (prior = 0; prior < index; prior++) {
      if (config->inbounds[prior].port == inbound->port &&
          memcmp(config->inbounds[prior].listen.value.v4,
                 inbound->listen.value.v4, 4u) == 0) {
        set_error(error, FN_CONFIG_ERROR_LISTENER_CONFLICT, path, item,
                  "Inbound listen endpoint conflicts with an earlier inbound.");
        return false;
      }
    }
  }
  return true;
}

static bool parse_proxies(const fn_yaml_node_t *sequence,
                          fn_config_t *config, fn_config_error_t *error)
{
  static const char *const allowed[] = {
    "name", "type", "server", "port", "username", "password", "udp",
  };
  const fn_yaml_node_t *item;
  size_t index = 0;
  if (sequence == NULL) {
    return true;
  }
  if (sequence->kind != FN_YAML_SEQUENCE) {
    set_error(error, FN_CONFIG_ERROR_TYPE, "proxies", sequence,
              "Expected a proxy sequence.");
    return false;
  }
  config->proxy_count = sequence_count(sequence);
  if (config->proxy_count > 4096u) {
    set_error(error, FN_CONFIG_ERROR_COLLECTION_LIMIT, "proxies", sequence,
              "Proxy collection limit exceeded.");
    return false;
  }
  if (!allocate_array(config, config->proxy_count,
                      sizeof(*config->proxies), (void **)&config->proxies,
                      error)) {
    return false;
  }
  for (item = sequence->first; item != NULL; item = item->next, index++) {
    fn_proxy_config_t *proxy = &config->proxies[index];
    const fn_yaml_node_t *node;
    const fn_yaml_node_t *username;
    const fn_yaml_node_t *password;
    char base[FN_CONFIG_PATH_MAX];
    char path[FN_CONFIG_PATH_MAX];
    size_t prior;
    path_index(base, "proxies", index);
    if (!validate_allowed_fields(item, base, allowed,
                                 sizeof(allowed) / sizeof(allowed[0]), error)) {
      return false;
    }
    node = mapping_get(item, "name");
    path_join(path, base, "name");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Proxy name is required.");
      return false;
    }
    if (!valid_object_name(node, path, proxy->name, error)) {
      return false;
    }
    if (strcmp(proxy->name, "DIRECT") == 0 ||
        strcmp(proxy->name, "REJECT") == 0) {
      set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
                "Proxy name is reserved.");
      return false;
    }
    for (prior = 0; prior < index; prior++) {
      if (strcmp(config->proxies[prior].name, proxy->name) == 0) {
        set_error(error, FN_CONFIG_ERROR_DUPLICATE_NAME, path, node,
                  "Proxy name is duplicated.");
        return false;
      }
    }
    node = mapping_get(item, "type");
    path_join(path, base, "type");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Proxy type is required.");
      return false;
    }
    if (!require_scalar(node, path, error)) {
      return false;
    }
    if (!scalar_equal(node, "socks5")) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, path, node,
                "Proxy type is not supported by V0.1.");
      return false;
    }
    node = mapping_get(item, "server");
    path_join(path, base, "server");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Proxy server is required.");
      return false;
    }
    if (!parse_server(node, path, &proxy->server, error)) {
      return false;
    }
    node = mapping_get(item, "port");
    path_join(path, base, "port");
    if (node == NULL) {
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Proxy port is required.");
      return false;
    }
    if (!parse_port(node, path, &proxy->port, error)) {
      return false;
    }
    username = mapping_get(item, "username");
    password = mapping_get(item, "password");
    if ((username == NULL) != (password == NULL)) {
      path_join(path, base, username == NULL ? "username" : "password");
      set_error(error, FN_CONFIG_ERROR_REQUIRED, path, item,
                "Proxy username and password must appear together.");
      return false;
    }
    if (username != NULL) {
      char username_path[FN_CONFIG_PATH_MAX];
      char password_path[FN_CONFIG_PATH_MAX];
      path_join(username_path, base, "username");
      path_join(password_path, base, "password");
      if (!copy_secret(username, username_path,
                       proxy->credentials.username,
                       &proxy->credentials.username_length, error) ||
          !copy_secret(password, password_path,
                       proxy->credentials.password,
                       &proxy->credentials.password_length, error)) {
        return false;
      }
      proxy->has_credentials = true;
    }
    node = mapping_get(item, "udp");
    path_join(path, base, "udp");
    if (node != NULL && !parse_bool(node, path, &proxy->udp, error)) {
      return false;
    }
    if (proxy->udp) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, path, node,
                "SOCKS UDP is not supported by V0.1.");
      return false;
    }
  }
  return true;
}

static bool parse_upstream(const fn_yaml_node_t *node, const char *path,
                           fn_dns_upstream_t *out,
                           fn_config_error_t *error)
{
  const char *text;
  const char *host;
  const char *colon;
  size_t host_length;
  char host_text[INET_ADDRSTRLEN];
  uint8_t address_bytes[4];
  uint64_t port = UINT64_C(53);
  fn_addr_t address;

  if (!require_scalar(node, path, error)) {
    return false;
  }
  text = node->scalar;
  host = text;
  out->transport = FN_DNS_TRANSPORT_UDP;
  if (strncmp(text, "udp://", 6u) == 0 || strncmp(text, "tcp://", 6u) == 0) {
    out->transport = text[0] == 'u' ? FN_DNS_TRANSPORT_UDP :
                                      FN_DNS_TRANSPORT_TCP;
    host = text + 6;
    colon = strrchr(host, ':');
    if (colon == NULL || colon == host) {
      set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
                "DNS upstream requires an IPv4 address and port.");
      return false;
    }
    host_length = (size_t)(colon - host);
    {
      char port_text[6];
      const size_t port_length = strlen(colon + 1);
      fn_yaml_node_t port_node = *node;
      if (port_length == 0 || port_length >= sizeof(port_text)) {
        set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
                  "DNS upstream port is outside 1..65535.");
        return false;
      }
      memcpy(port_text, colon + 1, port_length + 1u);
      port_node.scalar = port_text;
      port_node.scalar_length = port_length;
      if (!parse_u64(&port_node, path, &port, error)) {
        return false;
      }
    }
  } else {
    colon = NULL;
    host_length = strlen(host);
  }
  if (host_length == 0 || host_length >= sizeof(host_text) ||
      port == 0 || port > UINT16_MAX) {
    set_error(error, FN_CONFIG_ERROR_RANGE, path, node,
              "DNS upstream address or port is outside the supported range.");
    return false;
  }
  memcpy(host_text, host, host_length);
  host_text[host_length] = '\0';
  if (inet_pton(AF_INET, host_text, address_bytes) != 1 ||
      fn_addr_from_v4(&address, address_bytes).code != FN_OK ||
      fn_endpoint_make(&out->endpoint, &address,
                       (uint16_t)port).code != FN_OK) {
    set_error(error, FN_CONFIG_ERROR_FORMAT, path, node,
              "DNS upstream must use a numeric IPv4 address.");
    return false;
  }
  return true;
}

static bool parse_upstream_list(const fn_yaml_node_t *sequence,
                                const char *path, bool *present,
                                fn_dns_upstream_t output[16], size_t *count,
                                fn_config_error_t *error)
{
  const fn_yaml_node_t *item;
  size_t index = 0;
  *present = sequence != NULL;
  *count = 0;
  if (sequence == NULL) {
    return true;
  }
  if (sequence->kind != FN_YAML_SEQUENCE) {
    set_error(error, FN_CONFIG_ERROR_TYPE, path, sequence,
              "Expected a DNS upstream sequence.");
    return false;
  }
  *count = sequence_count(sequence);
  if (*count == 0 || *count > 16u) {
    set_error(error, *count == 0 ? FN_CONFIG_ERROR_RANGE :
              FN_CONFIG_ERROR_COLLECTION_LIMIT, path, sequence,
              "DNS upstream list is empty or too large.");
    return false;
  }
  for (item = sequence->first; item != NULL; item = item->next, index++) {
    char item_path[FN_CONFIG_PATH_MAX];
    size_t prior;
    path_index(item_path, path, index);
    if (!parse_upstream(item, item_path, &output[index], error)) {
      return false;
    }
    for (prior = 0; prior < index; prior++) {
      if (output[prior].transport == output[index].transport &&
          output[prior].endpoint.port == output[index].endpoint.port &&
          memcmp(output[prior].endpoint.address.value.v4,
                 output[index].endpoint.address.value.v4, 4u) == 0) {
        set_error(error, FN_CONFIG_ERROR_DUPLICATE_VALUE, item_path, item,
                  "DNS upstream is duplicated.");
        return false;
      }
    }
  }
  return true;
}

static bool parse_dns(const fn_yaml_node_t *mapping, fn_config_t *config,
                      fn_config_error_t *error)
{
  static const char *const allowed[] = {
    "enable", "bootstrap", "direct", "timeout", "attempts",
    "failure-cache-size", "failure-cache-ttl",
  };
  const fn_yaml_node_t *node;
  uint64_t value;
  if (mapping == NULL) {
    return true;
  }
  if (!validate_allowed_fields(mapping, "dns", allowed,
                               sizeof(allowed) / sizeof(allowed[0]), error)) {
    return false;
  }
  node = mapping_get(mapping, "enable");
  if (node != NULL && !parse_bool(node, "dns.enable", &config->dns.enable,
                                  error)) {
    return false;
  }
  if (config->dns.enable) {
    set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, "dns.enable", node,
              "DNS listener is not supported by V0.1.");
    return false;
  }
  if (!parse_upstream_list(mapping_get(mapping, "bootstrap"),
                           "dns.bootstrap", &config->dns.bootstrap_present,
                           config->dns.bootstrap,
                           &config->dns.bootstrap_count, error) ||
      !parse_upstream_list(mapping_get(mapping, "direct"), "dns.direct",
                           &config->dns.direct_present, config->dns.direct,
                           &config->dns.direct_count, error)) {
    return false;
  }
  node = mapping_get(mapping, "timeout");
  if (node != NULL &&
      (!parse_duration(node, "dns.timeout", &config->dns.timeout_ms, error) ||
       config->dns.timeout_ms < UINT64_C(10) ||
       config->dns.timeout_ms > UINT64_C(30000))) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_RANGE, "dns.timeout", node,
                "DNS timeout is outside 10ms..30s.");
    }
    return false;
  }
  node = mapping_get(mapping, "attempts");
  if (node != NULL) {
    if (!parse_u64(node, "dns.attempts", &value, error)) {
      return false;
    }
    if (value < 1u || value > 4u) {
      set_error(error, FN_CONFIG_ERROR_RANGE, "dns.attempts", node,
                "DNS attempts is outside 1..4.");
      return false;
    }
    config->dns.attempts = (uint32_t)value;
  }
  node = mapping_get(mapping, "failure-cache-size");
  if (node != NULL) {
    if (!parse_u64(node, "dns.failure-cache-size", &value, error)) {
      return false;
    }
    if (value < 1u || value > 65536u) {
      set_error(error, FN_CONFIG_ERROR_RANGE, "dns.failure-cache-size", node,
                "DNS failure cache size is outside 1..65536.");
      return false;
    }
    config->dns.failure_cache_size = (size_t)value;
  }
  node = mapping_get(mapping, "failure-cache-ttl");
  if (node != NULL &&
      (!parse_duration(node, "dns.failure-cache-ttl",
                       &config->dns.failure_cache_ttl_ms, error) ||
       config->dns.failure_cache_ttl_ms < UINT64_C(1000) ||
       config->dns.failure_cache_ttl_ms > UINT64_C(300000))) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_RANGE, "dns.failure-cache-ttl", node,
                "DNS failure cache TTL is outside 1s..5m.");
    }
    return false;
  }
  return true;
}

static void trim_span(const char **start, const char **end)
{
  while (*start < *end && (**start == ' ' || **start == '\t')) {
    (*start)++;
  }
  while (*end > *start && ((*end)[-1] == ' ' || (*end)[-1] == '\t')) {
    (*end)--;
  }
}

static bool parse_rules(const fn_yaml_node_t *sequence, fn_config_t *config,
                        fn_config_error_t *error)
{
  const fn_yaml_node_t *item;
  size_t index = 0;
  if (sequence == NULL) {
    set_error(error, FN_CONFIG_ERROR_REQUIRED, "rules", NULL,
              "At least one rule is required.");
    return false;
  }
  if (sequence->kind != FN_YAML_SEQUENCE) {
    set_error(error, FN_CONFIG_ERROR_TYPE, "rules", sequence,
              "Expected a rule sequence.");
    return false;
  }
  config->rule_count = sequence_count(sequence);
  if (config->rule_count == 0 || config->rule_count > 100000u) {
    set_error(error, config->rule_count == 0 ? FN_CONFIG_ERROR_RANGE :
              FN_CONFIG_ERROR_COLLECTION_LIMIT, "rules", sequence,
              "Rule collection is empty or too large.");
    return false;
  }
  if (!allocate_array(config, config->rule_count, sizeof(*config->rules),
                      (void **)&config->rules, error)) {
    return false;
  }
  for (item = sequence->first; item != NULL; item = item->next, index++) {
    const char *comma;
    const char *type_start;
    const char *type_end;
    const char *target_start;
    const char *target_end;
    size_t target_length;
    char path[FN_CONFIG_PATH_MAX];
    path_index(path, "rules", index);
    if (!require_scalar(item, path, error)) {
      return false;
    }
    if (item->scalar_length == 0 || item->scalar_length > FN_CONFIG_RULE_MAX) {
      set_error(error, FN_CONFIG_ERROR_RANGE, path, item,
                "Rule length is outside 1..1024 bytes.");
      return false;
    }
    comma = strchr(item->scalar, ',');
    if (comma == NULL || strchr(comma + 1, ',') != NULL) {
      set_error(error, FN_CONFIG_ERROR_FORMAT, path, item,
                "Rule must contain exactly one comma in V0.1.");
      return false;
    }
    type_start = item->scalar;
    type_end = comma;
    target_start = comma + 1;
    target_end = item->scalar + item->scalar_length;
    trim_span(&type_start, &type_end);
    trim_span(&target_start, &target_end);
    if ((size_t)(type_end - type_start) != 5u ||
        memcmp(type_start, "MATCH", 5u) != 0) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, path, item,
                "Only MATCH rules are supported by V0.1.");
      return false;
    }
    target_length = (size_t)(target_end - target_start);
    if (target_length == 0 || target_length > FN_CONFIG_NAME_MAX) {
      set_error(error, FN_CONFIG_ERROR_RANGE, path, item,
                "Rule target length is outside 1..64 bytes.");
      return false;
    }
    memcpy(config->rules[index].target, target_start, target_length);
    config->rules[index].target[target_length] = '\0';
    if (index + 1u != config->rule_count) {
      set_error(error, FN_CONFIG_ERROR_RULE_ORDER, path, item,
                "MATCH must be the final and only V0.1 rule.");
      return false;
    }
  }
  return true;
}

static const fn_proxy_config_t *find_proxy(const fn_config_t *config,
                                           const char *name)
{
  size_t index;
  for (index = 0; index < config->proxy_count; index++) {
    if (strcmp(config->proxies[index].name, name) == 0) {
      return &config->proxies[index];
    }
  }
  return NULL;
}

static bool validate_dependency_closure(const fn_config_t *config,
                                        fn_config_error_t *error)
{
  size_t index;
  for (index = 0; index < config->rule_count; index++) {
    const char *target = config->rules[index].target;
    char path[FN_CONFIG_PATH_MAX];
    path_index(path, "rules", index);
    if (strcmp(target, "DIRECT") == 0) {
      if (config->dns.direct_count == 0) {
        set_error(error, FN_CONFIG_ERROR_DNS_REQUIRED, "dns.direct", NULL,
                  "DIRECT domain paths require dns.direct.");
        return false;
      }
    } else if (strcmp(target, "REJECT") != 0) {
      const fn_proxy_config_t *proxy = find_proxy(config, target);
      if (proxy == NULL) {
        set_error(error, FN_CONFIG_ERROR_REFERENCE, path, NULL,
                  "Rule target does not exist.");
        return false;
      }
      if (proxy->server.kind == FN_ADDR_DOMAIN &&
          config->dns.bootstrap_count == 0) {
        set_error(error, FN_CONFIG_ERROR_DNS_REQUIRED, "dns.bootstrap", NULL,
                  "Domain proxy servers require dns.bootstrap.");
        return false;
      }
    }
  }
  return true;
}

static void config_defaults(fn_config_t *config, fn_allocator_t allocator)
{
  memset(config, 0, sizeof(*config));
  config->schema_version = UINT32_C(1);
  config->log_level = FN_LOG_WARN;
  config->limits = fn_limits_default();
  config->timeouts.handshake_ms = UINT64_C(10000);
  config->timeouts.connect_ms = UINT64_C(10000);
  config->timeouts.tcp_idle_ms = UINT64_C(300000);
  config->timeouts.drain_ms = UINT64_C(5000);
  config->timeouts.resource_wait_ms = UINT64_C(1000);
  config->timeouts.worker_task_ms = UINT64_C(30000);
  config->dns.timeout_ms = UINT64_C(2000);
  config->dns.attempts = UINT32_C(2);
  config->dns.failure_cache_size = (size_t)1024u;
  config->dns.failure_cache_ttl_ms = UINT64_C(5000);
  config->allocator = allocator;
}

static bool parse_root(const fn_yaml_node_t *root, fn_config_t *config,
                       fn_config_error_t *error)
{
  static const char *const allowed[] = {
    "schema-version", "mode", "log-level", "ipv6", "inbounds",
    "proxies", "rules", "limits", "timeouts", "dns",
  };
  const fn_yaml_node_t *node;
  uint64_t value;
  if (root->kind != FN_YAML_MAPPING) {
    set_error(error, FN_CONFIG_ERROR_TYPE, "", root,
              "Configuration root must be a mapping.");
    return false;
  }
  if (!validate_allowed_fields(root, "", allowed,
                               sizeof(allowed) / sizeof(allowed[0]), error)) {
    return false;
  }
  node = mapping_get(root, "schema-version");
  if (node != NULL) {
    if (!parse_u64(node, "schema-version", &value, error)) {
      return false;
    }
    if (value != UINT64_C(1)) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION,
                "schema-version", node,
                "Only schema-version 1 is supported.");
      return false;
    }
  }
  node = mapping_get(root, "mode");
  if (node != NULL &&
      (!require_scalar(node, "mode", error) || !scalar_equal(node, "rule"))) {
    if (error->code == FN_CONFIG_ERROR_NONE) {
      set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, "mode", node,
                "Only rule mode is supported.");
    }
    return false;
  }
  node = mapping_get(root, "log-level");
  if (node != NULL) {
    if (!require_scalar(node, "log-level", error)) {
      return false;
    }
    if (scalar_equal(node, "error")) config->log_level = FN_LOG_ERROR;
    else if (scalar_equal(node, "warn")) config->log_level = FN_LOG_WARN;
    else if (scalar_equal(node, "info")) config->log_level = FN_LOG_INFO;
    else if (scalar_equal(node, "debug")) config->log_level = FN_LOG_DEBUG;
    else if (scalar_equal(node, "trace")) config->log_level = FN_LOG_TRACE;
    else {
      set_error(error, FN_CONFIG_ERROR_RANGE, "log-level", node,
                "Unsupported log level.");
      return false;
    }
  }
  node = mapping_get(root, "ipv6");
  if (node != NULL && !parse_bool(node, "ipv6", &config->ipv6, error)) {
    return false;
  }
  if (config->ipv6) {
    set_error(error, FN_CONFIG_ERROR_UNSUPPORTED_VERSION, "ipv6", node,
              "IPv6 proxy targets are not supported by V0.1.");
    return false;
  }
  node = mapping_get(root, "limits");
  if (node != NULL && !parse_limits(node, config, error)) {
    return false;
  }
  node = mapping_get(root, "timeouts");
  if (node != NULL && !parse_timeouts(node, config, error)) {
    return false;
  }
  if (!parse_inbounds(mapping_get(root, "inbounds"), config, error) ||
      !parse_proxies(mapping_get(root, "proxies"), config, error) ||
      !parse_dns(mapping_get(root, "dns"), config, error) ||
      !parse_rules(mapping_get(root, "rules"), config, error) ||
      !validate_dependency_closure(config, error)) {
    return false;
  }
  return true;
}

/* fn_config_parse 建立有界 AST 和 Typed Config；失败保持 out 可安全销毁。 */
fn_result_t fn_config_parse(const uint8_t *input, size_t input_length,
                            fn_allocator_t allocator, fn_config_t *out,
                            fn_config_error_t *error)
{
  fn_yaml_node_t *root = NULL;
  fn_result_t result = config_result(FN_INVALID);

  clear_error(error);
  if (out == NULL || error == NULL || input == NULL ||
      allocator.allocate == NULL || allocator.deallocate == NULL) {
    set_error(error, FN_CONFIG_ERROR_TYPE, "", NULL,
              "Invalid parser arguments.");
    return config_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (input_length > FN_CONFIG_MAX_BYTES) {
    set_error(error, FN_CONFIG_ERROR_SIZE, "", NULL,
              "Configuration exceeds 1 MiB.");
    return config_result(FN_LIMIT);
  }
  config_defaults(out, allocator);
  if (!yaml_parse_document(input, input_length, allocator, &root, error)) {
    result = error->code == FN_CONFIG_ERROR_NO_MEMORY ?
             config_result(FN_NO_MEMORY) : config_result(FN_INVALID);
    fn_config_destroy(out);
    return result;
  }
  if (!validate_duplicate_keys(root, "", error) ||
      !parse_root(root, out, error)) {
    if (error->code == FN_CONFIG_ERROR_UNSUPPORTED_VERSION) {
      result = config_result(FN_UNSUPPORTED);
    } else if (error->code == FN_CONFIG_ERROR_NO_MEMORY) {
      result = config_result(FN_NO_MEMORY);
    }
    yaml_node_destroy(allocator, root);
    fn_config_destroy(out);
    return result;
  }
  yaml_node_destroy(allocator, root);
  return config_result(FN_OK);
}

/* fn_config_destroy 清除凭据并按所属 allocator 释放全部 Typed Config。 */
void fn_config_destroy(fn_config_t *config)
{
  size_t index;
  if (config == NULL || config->allocator.deallocate == NULL) {
    return;
  }
  if (config->inbounds != NULL) {
    for (index = 0; index < config->inbound_count; index++) {
      if (config->inbounds[index].users != NULL) {
        memset(config->inbounds[index].users, 0,
               config->inbounds[index].user_count *
               sizeof(*config->inbounds[index].users));
        config->allocator.deallocate(config->allocator.context,
                                     config->inbounds[index].users);
      }
    }
    config->allocator.deallocate(config->allocator.context, config->inbounds);
  }
  if (config->proxies != NULL) {
    memset(config->proxies, 0,
           config->proxy_count * sizeof(*config->proxies));
    config->allocator.deallocate(config->allocator.context, config->proxies);
  }
  if (config->rules != NULL) {
    config->allocator.deallocate(config->allocator.context, config->rules);
  }
  memset(config, 0, sizeof(*config));
}

/* fn_config_plan 只计算依赖闭包，不创建 fd、timer、worker 或网络请求。 */
fn_result_t fn_config_plan(const fn_config_t *config,
                           fn_feature_set_t available_features,
                           fn_feature_plan_t *out,
                           fn_config_error_t *error)
{
  size_t index;
  fn_feature_set_t required;
  clear_error(error);
  if (config == NULL || out == NULL || error == NULL) {
    set_error(error, FN_CONFIG_ERROR_TYPE, "", NULL,
              "Invalid planner arguments.");
    return config_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (config->inbound_count != 0) {
    out->reachable |= FN_FEATURE_SOCKS_IN_TCP;
    out->prepare |= FN_FEATURE_SOCKS_IN_TCP;
  }
  for (index = 0; index < config->rule_count; index++) {
    const char *target = config->rules[index].target;
    if (strcmp(target, "DIRECT") == 0) {
      out->reachable |= FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_RESOLVER |
                        FN_FEATURE_DNS_FAILURE_CACHE;
      out->lazy |= FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_RESOLVER |
                   FN_FEATURE_DNS_FAILURE_CACHE;
    } else if (strcmp(target, "REJECT") != 0) {
      const fn_proxy_config_t *proxy = find_proxy(config, target);
      out->reachable |= FN_FEATURE_SOCKS_OUT_TCP;
      out->lazy |= FN_FEATURE_SOCKS_OUT_TCP;
      if (proxy != NULL && proxy->server.kind == FN_ADDR_DOMAIN) {
        out->reachable |= FN_FEATURE_DNS_RESOLVER |
                          FN_FEATURE_DNS_FAILURE_CACHE;
        out->lazy |= FN_FEATURE_DNS_RESOLVER |
                     FN_FEATURE_DNS_FAILURE_CACHE;
      }
    }
  }
  if ((out->reachable & FN_FEATURE_DNS_RESOLVER) != 0) {
    for (index = 0; index < config->dns.direct_count; index++) {
      out->reachable |= config->dns.direct[index].transport ==
                        FN_DNS_TRANSPORT_UDP ? FN_FEATURE_DNS_UPSTREAM_UDP :
                                               FN_FEATURE_DNS_UPSTREAM_TCP;
    }
    for (index = 0; index < config->dns.bootstrap_count; index++) {
      out->reachable |= config->dns.bootstrap[index].transport ==
                        FN_DNS_TRANSPORT_UDP ? FN_FEATURE_DNS_UPSTREAM_UDP :
                                               FN_FEATURE_DNS_UPSTREAM_TCP;
    }
    out->lazy |= out->reachable & (FN_FEATURE_DNS_UPSTREAM_UDP |
                                   FN_FEATURE_DNS_UPSTREAM_TCP);
  }
  required = out->reachable;
  if ((required & ~available_features) != 0) {
    set_error(error, FN_CONFIG_ERROR_FEATURE_UNAVAILABLE, "", NULL,
              "Required feature is unavailable in this build.");
    memset(out, 0, sizeof(*out));
    return config_result(FN_FEATURE_UNAVAILABLE);
  }
  return config_result(FN_OK);
}

const char *fn_config_error_code_name(fn_config_error_code_t code)
{
  switch (code) {
    case FN_CONFIG_ERROR_NONE: return "";
    case FN_CONFIG_ERROR_SIZE: return "E_CONFIG_SIZE";
    case FN_CONFIG_ERROR_UTF8: return "E_UTF8";
    case FN_CONFIG_ERROR_YAML_SYNTAX: return "E_YAML_SYNTAX";
    case FN_CONFIG_ERROR_YAML_LIMIT: return "E_YAML_LIMIT";
    case FN_CONFIG_ERROR_YAML_UNSUPPORTED: return "E_YAML_UNSUPPORTED";
    case FN_CONFIG_ERROR_DUPLICATE_KEY: return "E_DUPLICATE_KEY";
    case FN_CONFIG_ERROR_UNKNOWN_FIELD: return "E_UNKNOWN_FIELD";
    case FN_CONFIG_ERROR_REQUIRED: return "E_REQUIRED";
    case FN_CONFIG_ERROR_NULL: return "E_NULL";
    case FN_CONFIG_ERROR_TYPE: return "E_TYPE";
    case FN_CONFIG_ERROR_FORMAT: return "E_FORMAT";
    case FN_CONFIG_ERROR_RANGE: return "E_RANGE";
    case FN_CONFIG_ERROR_OVERFLOW: return "E_OVERFLOW";
    case FN_CONFIG_ERROR_COLLECTION_LIMIT: return "E_COLLECTION_LIMIT";
    case FN_CONFIG_ERROR_UNSUPPORTED_VERSION: return "E_UNSUPPORTED_VERSION";
    case FN_CONFIG_ERROR_FEATURE_UNAVAILABLE: return "E_FEATURE_UNAVAILABLE";
    case FN_CONFIG_ERROR_DUPLICATE_NAME: return "E_DUPLICATE_NAME";
    case FN_CONFIG_ERROR_DUPLICATE_VALUE: return "E_DUPLICATE_VALUE";
    case FN_CONFIG_ERROR_REFERENCE: return "E_REFERENCE";
    case FN_CONFIG_ERROR_RULE_ORDER: return "E_RULE_ORDER";
    case FN_CONFIG_ERROR_LISTENER_CONFLICT: return "E_LISTENER_CONFLICT";
    case FN_CONFIG_ERROR_DNS_REQUIRED: return "E_DNS_REQUIRED";
    case FN_CONFIG_ERROR_RESOURCE_PLAN: return "E_RESOURCE_PLAN";
    case FN_CONFIG_ERROR_NO_MEMORY: return "E_INTERNAL";
  }
  return "E_INTERNAL";
}
