#include <zzutil/zzcapture.h>
#include <zzutil/errmsg.h>

#include "testutil.h"

int main() {
    int ret;
    int frame_size = 100;
    zzcapture_handle_t *hcap;
    zzcapture_param_t param = {
        .bit_rate = 40000,
        .height = 9 * 80,
        .width = 16 * 80,
    };
    u8 *data;
    size_t len;
    FILE *fp;

    fp = fopen("capture1.ts", "wb");
    assert(fp != NULL);

    zzcapture_init();

    ret = zzcapture_new(&hcap, &param, stderr);
    assert(ret == ZZECODE_OK);

    while (frame_size--) {
        ret = zzcapture_get_ts_packet(hcap, &data, &len);
        assert(ret == ZZECODE_OK);

        fwrite(data, 1, len, fp);

        free(data);
    }

    ret = zzcapture_release(&hcap);
    assert(ret == ZZECODE_OK);

    fclose(fp);

    // second capture

    frame_size = 100;

    fp = fopen("capture2.ts", "wb");
    assert(fp != NULL);

    ret = zzcapture_new(&hcap, &param, stderr);
    assert(ret == ZZECODE_OK);

    while (frame_size--) {
        ret = zzcapture_get_ts_packet(hcap, &data, &len);
        assert(ret == ZZECODE_OK);

        fwrite(data, 1, len, fp);

        free(data);
    }

    ret = zzcapture_release(&hcap);
    assert(ret == ZZECODE_OK);


    return 0;
}
