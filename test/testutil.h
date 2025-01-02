#ifndef TESTUTIL_H
#define TESTUTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

void pasue_on_exit();
void dosleep(int ms);
void dosleep_timeofday(int ms);

#endif
