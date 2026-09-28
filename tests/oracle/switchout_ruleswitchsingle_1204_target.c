/* Driver for the switchout_single.S fixture function. */
#include <stdio.h>

extern int sink_state;
int single_target_switch(unsigned int x);

int main(void)
{
    volatile unsigned v = 3u;
    int res = single_target_switch(v);
    printf("%d %d\n", res, sink_state);
    return 0;
}
