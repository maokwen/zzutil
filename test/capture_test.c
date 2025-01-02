#include <zzutil/zzcapture.h>
#include <zzutil/errmsg.h>

#include "testutil.h"

int main() {
    int ret;
    int frame_size = 200;
    zzcapture_handle_t *hcap;
    u8 *data;
    size_t len;
    FILE *fp;

    fp = fopen("capture_test.ts", "wb");
    assert(fp != NULL);

    ret = zzcapture_init(&hcap, stderr);
    assert(ret == ZZECODE_OK);

    while (frame_size--) {
        ret = zzcapture_get_ts_packet(hcap, &data, &len);
        assert(ret == ZZECODE_OK);

        fwrite(data, 1, len, fp);
    }

    fclose(fp);

    return 0;
}
