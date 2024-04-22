#ifndef _FUBUKI_H
#define _FUBUKI_H

#include <stddef.h>
#include <inttypes.h>

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
};

#define FUBUKI_START_OPTIONS_VERSION (1)
#define FUBUKI_START_OPTIONS_VERSION2 (2)

struct FubukiHandle *fubuki_start(struct FubukiStartOptions *opts,
                                  uint32_t version,
                                  char *error);

void fubuki_stop(struct FubukiHandle *handle);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _FUBUKI_H
