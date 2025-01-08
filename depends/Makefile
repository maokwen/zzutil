mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
project_dir := $(shell dirname $(current_dir))

ffmpeg-4.4.5.tar.xz:
	@echo "Downloading ffmpeg-4.4.5.tar.xz"
	@curl -O https://ffmpeg.org/releases/ffmpeg-4.4.5.tar.xz

ffmpeg-4.4.5: ffmpeg-4.4.5.tar.xz
	@echo "Unzipping ffmpeg-4.4.5.tar.xz"
	@tar -xf ffmpeg-4.4.5.tar.xz

configure-ffmpeg: ffmpeg-4.4.5 ffmpeg-4.4.5/ffbuild/config.mak
	@echo "Configuring ffmpeg"
	@cd ffmpeg-4.4.5 && \
	./configure \
	--prefix=$(project_dir)/lib/ffmpeg \
	--enable-shared --disable-static \
        --enable-static \
        --enable-libxcb \
        --enable-pic \
        --disable-all \
        --disable-shared \
        --disable-network \
        --disable-autodetect \
        --disable-debug \
        --disable-asm \
        --enable-avformat \
        --enable-avdevice \
        --enable-avcodec \
        --enable-swscale \
        --enable-swresample \
        --enable-xlib \
        --disable-doc \
        --enable-indev=xcbgrab \
        --enable-decoder=rawvideo \
        --enable-muxer=mpegts \
        --enable-encoder=libopenh264 \
        --enable-libopenh264

ffmpeg: configure-ffmpeg
	@echo "Installing ffmpeg"
	@cd ffmpeg-4.4.5 && \
	make -j && \
	make install

clean-ffmpeg:
	@echo "Cleaning ffmpeg"
	@rm -rf ffmpeg-4.4.5

openssl-3.0.15.tar.gz:
	@echo "Downloading openssl-3.0.15.tar.gz"
	@curl -O https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz

openssl-3.0.15: openssl-3.0.15.tar.gz
	@echo "Unzipping openssl-3.0.15.tar.gz"
	@tar -xf openssl-3.0.15.tar.gz

configure-openssl: openssl-3.0.15 openssl-3.0.15/Makefile
	@echo "Configuring openssl"
	@cd openssl-3.0.15 && \
	./Configure --prefix=$(project_dir)/lib/openssl \
	--release \
	no-deprecated \
	no-legacy \
	no-shared \
	no-afalgeng \
	no-async \
	no-autoalginit \
	no-autoerrinit \
	no-cached-fetch \
	no-capieng \
	no-cmp \
	no-cms \
	no-comp \
	no-ct \
	no-dgram \
	no-dgram \
	no-dso \
	no-engine \
	no-err \
	no-filenames \
	no-gost \
	no-module \
	no-nextprotoneg \
	no-ocsp \
	no-padlockeng \
	no-pinshared \
	no-psk \
	no-rfc3779 \
	no-sock \
	no-srp \
	no-srtp \
	no-sse2 \
	no-ssl-trace \
	no-static-engine \
	no-stdio \
	no-tests \
	no-threads \
	no-ts \
	no-ui-console \
	no-uplink \
	no-tls \
	no-dtls \
	no-aria \
	no-bf \
	no-blake2 \
	no-camellia \
	no-cast \
	no-chacha \
	no-cmac \
    no-des \
	no-dh \
	no-dsa \
	no-ecdh \
	no-ecdsa \
	no-idea \
	no-md4 \
	no-mdc2 \
	no-ocb \
    no-poly1305 \
	no-rc2 \
	no-rc4 \
	no-rmd160 \
	no-scrypt \
	no-seed \
    no-siphash \
	no-siv \
	no-whirlpool \
	
openssl: configure-openssl
	@echo "Installing openssl"
	@cd openssl-3.0.15 && \
	make -j && \
	make install_sw

