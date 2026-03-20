#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include <libheif/heif.h>

static std::vector<uint8_t> read_file(const char* path) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return {};

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size <= 0 || file_size > (32 * 1024 * 1024)) {
        fclose(fp);
        return {};
    }
    fseek(fp, 0, SEEK_SET);

    std::vector<uint8_t> buf((size_t)file_size);
    if (fread(buf.data(), 1, buf.size(), fp) != buf.size()) {
        fclose(fp);
        return {};
    }

    fclose(fp);
    return buf;
}

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    auto data = read_file(argv[1]);
    if (data.empty()) return 0;

    heif_context* ctx = heif_context_alloc();
    if (!ctx) return 0;

    heif_error err = heif_context_read_from_memory_without_copy(
        ctx, data.data(), data.size(), nullptr);
    if (err.code != heif_error_Ok) { 
        heif_context_free(ctx);
        return 0;
    }

    heif_image_handle* handle = nullptr;
    err = heif_context_get_primary_image_handle(ctx, &handle);
    if (err.code != heif_error_Ok || !handle) {
        heif_context_free(ctx);
        return 0;
    }

    heif_decoding_options* opts = heif_decoding_options_alloc();
    heif_image* img = nullptr;
    err = heif_decode_image(
        handle, &img, heif_colorspace_RGB, heif_chroma_interleaved_RGB, opts);
    if (opts) heif_decoding_options_free(opts);

    if (err.code == heif_error_Ok && img) {
        size_t stride = 0;
        const uint8_t* plane = heif_image_get_plane_readonly2(
            img, heif_channel_interleaved, &stride);
        if (plane && stride > 0) {
            volatile uint8_t sink = plane[0];
            (void)sink;
        }
        heif_image_release(img);
    }

    heif_image_handle_release(handle);
    heif_context_free(ctx);
    return 0;
}
