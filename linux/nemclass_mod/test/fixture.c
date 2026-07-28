// SPDX-License-Identifier: GPL-2.0
/*
 * nemclass_mod test fixture.
 *
 * Holds known values at stable addresses and mutates one of them in a loop so
 * a write-watchpoint has something to fire on. Prints its pid and the target
 * addresses on startup; feed those to ./nemclient.
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/* volatile so the compiler keeps the loads/stores the watchpoint expects. */
volatile uint64_t nem_secret  = 0x1122334455667788ULL;	/* read/write target */
volatile uint64_t nem_counter = 0;			/* write every loop  */

int main(void)
{
	printf("pid=%d\n", getpid());
	printf("secret_addr=%p secret_val=0x%016llx\n",
	       (void *)&nem_secret, (unsigned long long)nem_secret);
	printf("counter_addr=%p\n", (void *)&nem_counter);
	fflush(stdout);

	for (;;) {
		nem_counter++;			/* fires a write-watchpoint */
		if ((nem_counter & 0xff) == 0)
			nem_secret ^= 0x1;
		usleep(200000);			/* 200 ms */
	}
	return 0;
}
