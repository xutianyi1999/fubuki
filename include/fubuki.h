#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>

struct Handle;

extern "C" {

void if_to_fubuki(const Handle *handle, const uint8_t *packet, uintptr_t len);

Handle *fubuki_start(const char *node_config_json,
                     void *ctx,
                     void (*fubuki_to_if_fn)(const uint8_t *packet, uintptr_t len, void *ctx),
                     void (*add_addr_fn)(uint8_t addr[4], uint8_t netmask[4], void *ctx),
                     void (*delete_addr_fn)(uint8_t addr[4], uint8_t netmask[4], void *ctx),
                     uint32_t device_index,
                     char *error);

void fubuki_stop(Handle *handle);

} // extern "C"
