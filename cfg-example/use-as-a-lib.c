// static: gcc -I ../include ../target/release/libfubuki.a ./use-as-a-lib.c -o use-as-a-lib
// static macos: add: -framework CoreFoundation -framework SystemConfiguration
// shared: gcc -I ../include -L ../target/release -lfubuki ./use-as-a-lib.c -o use-as-a-lib

#include <stdio.h>
#include <unistd.h>
#include "fubuki.h"

void pktrcv(const uint8_t *packet, size_t len, void *ctx) {
    printf("received packet: len=%lu\n", len);
}

void addip(uint32_t addr, uint32_t netmask, void *ctx) {
    printf("addip: addr=%u netmask=%u\n", addr, netmask);
    if (addr == 0) {
        return;
    }
    printf("need to add ip: %u.%u.%u.%u/%u.%u.%u.%u\n",
        (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff,
        (netmask >> 24) & 0xff, (netmask >> 16) & 0xff, (netmask >> 8) & 0xff, netmask & 0xff);
}

void delip(uint32_t addr, uint32_t netmask, void *ctx) {
    printf("delip: addr=%u netmask=%u\n", addr, netmask);
    if (addr == 0) {
        return;
    }
    printf("need to remove ip: %u.%u.%u.%u/%u.%u.%u.%u\n",
            (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff,
            (netmask >> 24) & 0xff, (netmask >> 16) & 0xff, (netmask >> 8) & 0xff, netmask & 0xff);
}

int main() {
    char *config = "{"
        "\"groups\": ["
            "{"
                "\"node_name\": \"my-node\","
                "\"server_addr\": \"1.2.3.4:56789\","
                "\"key\": \"123\""
            "}"
        "],"
        "\"features\": {"
            "\"disable_api_server\": true,"
            "\"disable_hosts_operation\": true,"
            "\"disable_signal_handling\": true,"
            "\"disable_route_operation\": true"
        "}"
    "}";

    char error[1024];
    struct FubukiStartOptions opts = {
        .ctx = NULL,
        .node_config_json = config,
        .device_index = 0,
        .fubuki_to_if_fn = pktrcv,
        .add_addr_fn = addip,
        .delete_addr_fn = delip,
    };
    struct FubukiHandle *handle = fubuki_start(&opts, 1, error);

    if (handle == NULL) {
        printf("%s\n", error);
        return 1;
    }

    printf("fubuki started, the sample program will run for 60 seconds\n");
    sleep(60);
    printf("calling fubuki_stop(...) now\n");

    fubuki_stop(handle);

    printf("terminating ...\n");
    return 0;
}
