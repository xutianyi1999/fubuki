#ifndef _FUBUKI_H
#define _FUBUKI_H

#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct FubukiHandle;

void if_to_fubuki(const struct FubukiHandle *handle, const uint8_t *packet, size_t len);

struct FubukiStartOptions {
  // user data
  void *ctx;
  // json string as config
  // V1 and V2 required
  const char *node_config_json;
  // index of the virtual device
  // V1 required
  uint32_t device_index;
  // the callback function to provide packets to the user program, packet starts from the header of the ip packet
  // V1 required
  void (*fubuki_to_if_fn)(const uint8_t *packet, size_t len, void *ctx);
  // the callback function to notify user program an ip should be added
  // V1 required
  void (*add_addr_fn)(uint32_t addr, uint32_t netmask, void *ctx);
  // the callback function to notify user program an ip should be deleted
  // V1 required
  void (*delete_addr_fn)(uint32_t addr, uint32_t netmask, void *ctx);
  // tun device file descriptor
  // V2 required
  int32_t tun_fd;
  // flags
  // V3 required
  uint64_t flags;
};

#define FUBUKI_START_OPTIONS_VERSION (1)
#define FUBUKI_START_OPTIONS_VERSION2 (2)
#define FUBUKI_START_OPTIONS_VERSION3 (3)

// need to use fubuki_block_on to launch fubuki if this flag is set
#define FUBUKI_FLAG_NO_AUTO_SPAWN (0x0001)

struct FubukiHandle *fubuki_start(struct FubukiStartOptions *opts,
                                  uint32_t version,
                                  char *error);

int32_t fubuki_block_on(struct FubukiHandle *handle, char *error);

void fubuki_stop(struct FubukiHandle *handle);

const char *fubuki_version();

void interfaces_info(struct FubukiHandle *handle, char *interfaces_info_json);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _FUBUKI_H
