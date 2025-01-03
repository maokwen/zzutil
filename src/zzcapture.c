#include "zzutil/zzcapture.h"
#include "zzutil/errmsg.h"

#include "common/helper.h"

#include <stdio.h>
#include <stdbool.h>

#include <libavutil/error.h>
#include <libavdevice/avdevice.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>

#ifndef MK_DEBUG
#define DEBUG_DIABLE if (true)
#endif

#define ERR_SIZE 256
#define BUF_SIZE 40960

#define LOG(fmt, ...)                              \
    if (log_output) {                              \
        fprintf(log_output, "zzcapture ");         \
        fprintf(log_output, (fmt), ##__VA_ARGS__); \
    }

typedef struct zzcapture_handle_ hcap_t;
typedef struct zzcapture_param parm_t;

struct zzcapture_handle_ {
    bool is_initialized;
    AVFormatContext *ifmt_ctx;
    AVCodecContext *icodec_ctx;
    AVFormatContext *ofmt_ctx;
    AVCodecContext *ocodec_ctx;
    int istream_idx;
    AVStream *ostream;
    AVFrame *iframe;
    AVFrame *oframe;
    struct SwsContext *sws_ctx;
};

static FILE *log_output = NULL;

bool ffmpeg_err(int ret) {
    if (ret >= 0) {
        return false;
    }
    if (log_output != NULL) {
        char str[ERR_SIZE];
        av_strerror(ret, str, ERR_SIZE);
        fprintf(log_output, "ffmpeg err: %s\n", str);
    }
    return true;
}

// impl

void free_hcap(hcap_t *hcap) {
    if (hcap->ifmt_ctx != NULL) {
        avformat_free_context(hcap->ifmt_ctx);
    }
    if (hcap->icodec_ctx != NULL) {
        avcodec_free_context(&hcap->icodec_ctx);
    }
    if (hcap->ofmt_ctx != NULL) {
        avformat_free_context(hcap->ofmt_ctx);
    }
    if (hcap->ocodec_ctx != NULL) {
        avcodec_free_context(&hcap->ocodec_ctx);
    }
    if (hcap->iframe != NULL) {
        av_frame_free(&hcap->iframe);
    }
    if (hcap->oframe != NULL) {
        av_frame_free(&hcap->oframe);
    }
    if (hcap->sws_ctx != NULL) {
        sws_freeContext(hcap->sws_ctx);
    }
}

int init_input(hcap_t *hcap) {
    int ret;
#ifdef _WIN32
    const char *ifmt_name = "gdigrab";
    const char *ifmt_url = "desktop";
#endif
#ifdef _UNIX
    const char *ifmt_name = "x11grab";
    // const char *ifmt_name = "xcbgrab";
    char *env_display = getenv("DISPLAY");
    if (env_display == NULL) {
        return ZZECODE_X_ERR;
    }
    char *ifmt_url = NULL;
    {
        int ifmt_url_len = strlen(env_display) + 1;
        ifmt_url = (char *)malloc(ifmt_url_len);
        strncpy(ifmt_url, env_display, ifmt_url_len);
        LOG("using display %s\n", ifmt_url);
    }
#endif

    /* list all input formats */ DEBUG_DIABLE {
        const AVInputFormat *f = NULL;
        void *i = 0;
        LOG("input formats:\n");
        while ((f = av_demuxer_iterate(&i))) {
            LOG("%s\n", f->name);
        }
    }

    const AVInputFormat *ifmt = av_find_input_format(ifmt_name);
    if (ifmt == NULL) {
        LOG("input format %s not found\n", ifmt_name);
        return ZZECODE_FFMPEG_ERR;
    }

    AVDictionary *ioptions = NULL;
    av_dict_set(&ioptions, "framerate", "25", 0);

    AVFormatContext *ifmt_ctx = avformat_alloc_context();
    hcap->ifmt_ctx = ifmt_ctx;

    ret = avformat_open_input(&ifmt_ctx, ifmt_url, (AVInputFormat *)ifmt,
                              &ioptions);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    /* find video stream */
    int istream_idx = 0;
    for (int i = 0; i < ifmt_ctx->nb_streams; ++i) {
        AVStream *stream = ifmt_ctx->streams[i];
        AVCodecParameters *codec_par = stream->codecpar;
        printf("%d: %d\n", i, codec_par->codec_id);
        if (codec_par->codec_type == AVMEDIA_TYPE_VIDEO) {
            istream_idx = i;
            hcap->istream_idx = istream_idx;
            break;
        }
    }

    AVCodecParameters *icodec_par = ifmt_ctx->streams[istream_idx]->codecpar;
    if (icodec_par == NULL) {
        LOG("codecpar not found\n");
        return ZZECODE_FFMPEG_ERR;
    }

    /* list all codecs */ DEBUG_DIABLE {
        const AVCodec *c = NULL;
        void *i = 0;
        while ((c = av_codec_iterate(&i))) {
            LOG("codeces:");
            LOG("%s: %d\n", c->name, c->id);
            if (c->id == icodec_par->codec_id) {
                LOG("codec %s found\n", c->name);
            }
        }
    }

    const AVCodec *icodec = avcodec_find_decoder(icodec_par->codec_id);
    if (icodec == NULL) {
        LOG("codec not found\n");
        return ZZECODE_FFMPEG_ERR;
    }

    AVCodecContext *icodec_ctx = avcodec_alloc_context3(icodec);
    hcap->icodec_ctx = icodec_ctx;

    ret = avcodec_parameters_to_context(icodec_ctx, icodec_par);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    ret = avcodec_open2(icodec_ctx, icodec, NULL);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    return ZZECODE_OK;
}

int init_output(hcap_t *hcap, const parm_t *parm) {
    int ret;

    const AVOutputFormat *ofmt = av_guess_format("mpegts", NULL, NULL);
    if (ofmt == NULL) {
        LOG("output format not found\n");
        return ZZECODE_FFMPEG_ERR;
    }

    AVFormatContext *ofmt_ctx = avformat_alloc_context();
    hcap->ofmt_ctx = ofmt_ctx;

    ret = avformat_alloc_output_context2(&ofmt_ctx, (AVOutputFormat *)ofmt, NULL, NULL);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    AVCodecParameters *ocodec_par = avcodec_parameters_alloc();
    {
        ocodec_par->codec_id = AV_CODEC_ID_H264;
        ocodec_par->height = parm->height;
        ocodec_par->width = parm->width;
        ocodec_par->bit_rate = parm->bit_rate;
        ocodec_par->codec_type = AVMEDIA_TYPE_VIDEO;
        ocodec_par->format = AV_PIX_FMT_YUV420P;
    }

    const AVCodec *ocodec = avcodec_find_encoder(ocodec_par->codec_id);
    if (ocodec == NULL) {
        LOG("output codec not found\n");
        return ZZECODE_FFMPEG_ERR;
    }

    AVStream *ostream = avformat_new_stream(ofmt_ctx, NULL);
    hcap->ostream = ostream;

    AVCodecContext *ocodec_ctx = avcodec_alloc_context3(ocodec);
    hcap->ocodec_ctx = ocodec_ctx;

    ret = avcodec_parameters_copy(ostream->codecpar, ocodec_par);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    ocodec_ctx->time_base.num = 1;
    ocodec_ctx->time_base.den = 25;

    ret = avcodec_parameters_to_context(ocodec_ctx, ocodec_par);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    ret = avformat_write_header(ofmt_ctx, NULL);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    ret = avcodec_open2(ocodec_ctx, ocodec, NULL);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    return ZZECODE_OK;
}

int init_frame_buffer(hcap_t *hcap) {
    int ret;
    AVCodecContext *icodec_ctx = hcap->icodec_ctx;
    AVCodecContext *ocodec_ctx = hcap->ocodec_ctx;

    AVFrame *iframe = av_frame_alloc();
    iframe->width = icodec_ctx->width;
    iframe->height = icodec_ctx->height;
    iframe->format = icodec_ctx->pix_fmt;
    ret = av_frame_get_buffer(iframe, 0);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    AVFrame *oframe = av_frame_alloc();
    oframe->width = ocodec_ctx->width;
    oframe->height = ocodec_ctx->height;
    oframe->format = ocodec_ctx->pix_fmt;
    av_frame_get_buffer(oframe, 0);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    hcap->iframe = iframe;
    hcap->oframe = oframe;

    return ZZECODE_OK;
}

int init_scale(hcap_t *hcap) {
    AVCodecContext *icodec_ctx = hcap->icodec_ctx;
    AVCodecContext *ocodec_ctx = hcap->ocodec_ctx;

    struct SwsContext *sws_ctx =
        sws_getContext(icodec_ctx->width, icodec_ctx->height, icodec_ctx->pix_fmt,
                       ocodec_ctx->width, ocodec_ctx->height, ocodec_ctx->pix_fmt,
                       SWS_FAST_BILINEAR, NULL, NULL, NULL);

    if (sws_ctx == NULL) {
        LOG("sws_getContext failed\n");
        return ZZECODE_FFMPEG_ERR;
    }

    hcap->sws_ctx = sws_ctx;

    return ZZECODE_OK;
}

int init(hcap_t **hcap, const parm_t *parm) {
    int ret;

    // regidter all devices
    avdevice_register_all();

    hcap_t *h = (*hcap) = malloc(sizeof(hcap_t));
    h->is_initialized = false;
    AVFormatContext *ifmt_ctx = h->ifmt_ctx = NULL;
    AVCodecContext *icodec_ctx = h->icodec_ctx = NULL;
    AVFormatContext *ofmt_ctx = h->ofmt_ctx = NULL;
    AVCodecContext *ocodec_ctx = h->ocodec_ctx = NULL;
    int istream_idx = h->istream_idx = 0;
    AVStream *ostream = h->ostream = NULL;
    AVFrame *iframe = h->iframe = NULL;
    AVFrame *oframe = h->oframe = NULL;
    struct SwsContext *sws_ctx = h->sws_ctx = NULL;

    // 1. initialize input format & codec context
    ret = init_input(h);
    if (ret != ZZECODE_OK) {
        free_hcap(h);
        return ret;
    }

    // 2. initialize output format & codec context
    ret = init_output(h, parm);
    if (ret != ZZECODE_OK) {
        free_hcap(h);
        return ret;
    }

    /* dump format */ DEBUG_DIABLE {
        // av_dump_format(ifmt_ctx, 0, NULL, 0);
        // av_dump_format(ofmt_ctx, 0, NULL, 1);
    }

    // 3. initialize freame buffer
    ret = init_frame_buffer(h);
    if (ret != ZZECODE_OK) {
        free_hcap(h);
        return ret;
    }

    // 4. initialize scale context
    ret = init_scale(h);
    if (ret != ZZECODE_OK) {
        free_hcap(h);
        return ret;
    }

    return ZZECODE_OK;
}

int get_ts_packet(const hcap_t *hcap, uint8_t **data, size_t *len) {
    int ret;
    AVFormatContext *ifmt_ctx = hcap->ifmt_ctx;
    AVCodecContext *icodec_ctx = hcap->icodec_ctx;
    AVFormatContext *ofmt_ctx = hcap->ofmt_ctx;
    AVCodecContext *ocodec_ctx = hcap->ocodec_ctx;
    int istream_idx = hcap->istream_idx;
    AVStream *ostream = hcap->ostream;
    AVFrame *iframe = hcap->iframe;
    AVFrame *oframe = hcap->oframe;
    struct SwsContext *sws_ctx = hcap->sws_ctx;

    AVPacket *ipacket = av_packet_alloc();
    AVPacket *opacket = av_packet_alloc();

    /* read from video frame */
    do {
        ret = av_read_frame(ifmt_ctx, ipacket);
        if (ffmpeg_err(ret)) {
            return ZZECODE_FFMPEG_ERR;
        }
    } while (ipacket->stream_index != istream_idx);

    ret = avcodec_send_packet(icodec_ctx, ipacket);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }
    ret = avcodec_receive_frame(icodec_ctx, iframe);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    /* copy & compress */ {
        opacket->data = NULL;
        opacket->size = 0;

        printf("ipacket: pts: %ld dts: %ld duration: %ld\n", ipacket->pts,
               ipacket->dts, ipacket->duration);
        printf("iframe: pts: %ld\n", iframe->pts);

        opacket->pts =
            av_rescale_q(ipacket->pts, ocodec_ctx->time_base, ostream->time_base);
        opacket->dts =
            av_rescale_q(ipacket->dts, ocodec_ctx->time_base, ostream->time_base);
        opacket->duration = av_rescale_q(ipacket->duration, ocodec_ctx->time_base,
                                         ostream->time_base);
        oframe->pts =
            av_rescale_q(iframe->pts, ocodec_ctx->time_base, ostream->time_base);
        oframe->pkt_duration = av_rescale_q(
            iframe->pkt_duration, ocodec_ctx->time_base, ostream->time_base);

        printf("opacket: pts: %ld dts: %ld duration: %ld\n", opacket->pts,
               opacket->dts, opacket->duration);

        printf("oframe: pts: %ld\n", oframe->pts);

        int _ = sws_scale(sws_ctx, (const uint8_t *const *)iframe->data,
                          iframe->linesize, 0, icodec_ctx->height, oframe->data,
                          oframe->linesize);

        printf("sws_scale: %d\n", _);

        ret = av_frame_make_writable(oframe);
        if (ffmpeg_err(ret)) {
            return ZZECODE_FFMPEG_ERR;
        }
    }

    ret = avcodec_send_frame(ocodec_ctx, oframe);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }
    ret = avcodec_receive_packet(ocodec_ctx, opacket);
    if (ffmpeg_err(ret)) {
        return ZZECODE_FFMPEG_ERR;
    }

    /* copy to dist */ {
        *data = malloc(opacket->size);
        *len = opacket->size;
        memcpy(*data, opacket->data, opacket->size);
    }

    av_packet_free(&ipacket);
    av_packet_free(&opacket);

    return ZZECODE_OK;
}

// exports

int zzcapture_init(zzcapture_handle_t **hcap, const zzcapture_param_t *param, FILE *log) {
    log_output = log;
    return init(hcap, param);
}

int zzcapture_get_ts_packet(const zzcapture_handle_t *hcap, uint8_t **data, size_t *len) {
    return get_ts_packet(hcap, data, len);
}
