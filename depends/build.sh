#!/bin/sh

parse_args()
  while test $# -gt 0; do
    case $1 in
    (-j)
        if [ -z $2 ]; then
            MAKE_J=
        else
            MAKE_J=$2
            shift
        fi
      ;;
    (*)
      PARAMS=$1
      ;;
    esac
    shift
  done

MAKE_J=1
parse_args "$@"
echo "MAKE_J=$MAKE_J"

SCRIPT_DIR=$(dirname $(readlink -f $0))
PROJ_DIR=$SCRIPT_DIR/..
PREFIX=$PROJ_DIR/lib/ffmpeg

printf "PREFIX=$PREFIX\n"

(
    cd $SCRIPT_DIR/ffmpeg-4.4.5 &&
    ./configure --enable-static --enable-pic --prefix=$PREFIX
)

mkdir -p $PREFIX
if [ $MAKE_J -eq 1 ]; then
    (cd $SCRIPT_DIR/ffmpeg-4.4.5 && make install)
else
    (cd $SCRIPT_DIR/ffmpeg-4.4.5 && make -j $MAKE_J install)
fi
