/* ---- 0x401166: single_target_switch (4 bytes) ---- */

typedef unsigned char byte;
typedef unsigned long undefined;
typedef unsigned short undefined2;
typedef unsigned long undefined4;
typedef unsigned long long undefined8;
typedef struct { char _anon[256]; } _struct;

/* WARNING: Switch with 1 destination removed at 0x40117a: 8 cases all go to same destination */

int4 single_target_switch(int4 param_1)

{
  return param_1 + 1;
}
