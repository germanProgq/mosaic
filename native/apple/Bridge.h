#include <stdint.h>
#include <stddef.h>
int32_t mosaic_validate_profile(const uint8_t *, size_t);
uint64_t mosaic_start(const uint8_t *, size_t);
uint64_t mosaic_start_in(const uint8_t *, size_t, const uint8_t *, size_t);
void mosaic_stop(uint64_t);
int32_t mosaic_socket(uint64_t);
void mosaic_socket_ready(uint64_t, int32_t, int32_t);
int32_t mosaic_needs_network(uint64_t);
void mosaic_network_ready(uint64_t, int32_t);
void mosaic_path_changed(uint64_t);
int32_t mosaic_settings(uint64_t, uint8_t *, size_t);
int32_t mosaic_status(uint64_t, uint8_t *, size_t);
int32_t mosaic_write_packet(uint64_t, const uint8_t *, size_t);
int32_t mosaic_read_packet(uint64_t, uint8_t *, size_t);
