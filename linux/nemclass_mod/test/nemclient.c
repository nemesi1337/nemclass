// SPDX-License-Identifier: GPL-2.0
/*
 * nemclient — userspace exerciser for /dev/nemclass.
 *
 * Usage:
 *   nemclient <keyhex> version
 *   nemclient <keyhex> read    <pid> <hexaddr> <len>
 *   nemclient <keyhex> write   <pid> <hexaddr> <hexbytes>
 *   nemclient <keyhex> regions <pid>
 *   nemclient <keyhex> watch   <pid> <hexaddr> <len>   # W watchpoint, streams hits
 *   nemclient <keyhex> uprobe  <pid> <hexaddr>         # exec breakpoint, streams hits
 *   nemclient <keyhex> ptrace  <pid>                   # query TracerPid
 *   nemclient <keyhex> hide    <pid>                   # spoof TracerPid=0 (needs allow_ptrace_hide=1)
 *
 * <keyhex> must equal the module's key= parameter (raw hex, no 0x).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <nemclass.h>

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { (void)sig; stop = 1; }

static int hexstr_to_bytes(const char *s, uint8_t *out, size_t out_cap, uint32_t *out_len)
{
	size_t slen = strlen(s);

	if (slen % 2 || slen / 2 > out_cap)
		return -1;
	for (size_t i = 0; i < slen / 2; i++) {
		unsigned int b;

		if (sscanf(s + 2 * i, "%2x", &b) != 1)
			return -1;
		out[i] = (uint8_t)b;
	}
	*out_len = (uint32_t)(slen / 2);
	return 0;
}

static int do_auth(int fd, const char *keyhex)
{
	struct nemclass_auth a;

	memset(&a, 0, sizeof(a));
	if (hexstr_to_bytes(keyhex, a.key, sizeof(a.key), &a.key_len)) {
		fprintf(stderr, "bad key hex\n");
		return -1;
	}
	if (ioctl(fd, NEMCLASS_IOC_AUTH, &a)) {
		perror("AUTH");
		return -1;
	}
	return 0;
}

static const char *bp_type_of(const char *s, uint32_t *out)
{
	if (!strcmp(s, "x")) { *out = NEMCLASS_BP_X;  return NULL; }
	if (!strcmp(s, "w")) { *out = NEMCLASS_BP_W;  return NULL; }
	if (!strcmp(s, "r")) { *out = NEMCLASS_BP_R;  return NULL; }
	if (!strcmp(s, "rw")){ *out = NEMCLASS_BP_RW; return NULL; }
	return "type must be x|w|r|rw";
}

static void print_event(const struct nemclass_event *e)
{
	printf("HIT slot=%d pid=%d tid=%d kind=%u addr=0x%llx ip=0x%llx sp=0x%llx\n",
	       e->slot, e->pid, e->tid, e->kind,
	       (unsigned long long)e->addr, (unsigned long long)e->ip,
	       (unsigned long long)e->sp);
	printf("    ax=0x%llx bx=0x%llx cx=0x%llx dx=0x%llx si=0x%llx di=0x%llx\n",
	       (unsigned long long)e->ax, (unsigned long long)e->bx,
	       (unsigned long long)e->cx, (unsigned long long)e->dx,
	       (unsigned long long)e->si, (unsigned long long)e->di);
}

/* Set a breakpoint and stream hits until Ctrl-C, then clear it. */
static int stream_breakpoint(int fd, struct nemclass_bp_set *bp)
{
	if (ioctl(fd, NEMCLASS_IOC_BP_SET, bp)) {
		perror("BP_SET");
		return -1;
	}
	printf("breakpoint armed (slot=%d); waiting for hits, Ctrl-C to stop\n", bp->slot);
	signal(SIGINT, on_sigint);

	while (!stop) {
		struct nemclass_event ev;
		struct nemclass_wait w;

		memset(&w, 0, sizeof(w));
		w.ubuf = (uint64_t)(uintptr_t)&ev;
		w.timeout_ms = 500;
		if (ioctl(fd, NEMCLASS_IOC_WAIT_EVENT, &w)) {
			if (errno == ETIMEDOUT || errno == EAGAIN)
				continue;
			if (errno == EINTR)
				break;
			perror("WAIT_EVENT");
			break;
		}
		print_event(&ev);
	}

	struct nemclass_bp_clear c = { .slot = bp->slot };
	ioctl(fd, NEMCLASS_IOC_BP_CLEAR, &c);
	printf("breakpoint cleared\n");
	return 0;
}

int main(int argc, char **argv)
{
	int fd, ret = 0;
	const char *keyhex, *cmd;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <keyhex> <cmd> ...\n", argv[0]);
		return 2;
	}
	keyhex = argv[1];
	cmd = argv[2];

	fd = open("/dev/nemclass", O_RDWR);
	if (fd < 0) {
		perror("open /dev/nemclass");
		return 1;
	}

	if (!strcmp(cmd, "version")) {
		struct nemclass_version v = {0};

		if (ioctl(fd, NEMCLASS_IOC_VERSION, &v)) { perror("VERSION"); ret = 1; }
		else printf("abi=%u\n", v.abi);
		goto out;
	}

	if (do_auth(fd, keyhex)) { ret = 1; goto out; }

	if (!strcmp(cmd, "read") && argc == 6) {
		struct nemclass_rw rw = {0};
		int pid = atoi(argv[3]);
		uint64_t addr = strtoull(argv[4], NULL, 16);
		uint64_t len = strtoull(argv[5], NULL, 0);
		uint8_t *buf = calloc(1, len ? len : 1);

		rw.pid = pid; rw.addr = addr; rw.len = len;
		rw.ubuf = (uint64_t)(uintptr_t)buf;
		if (ioctl(fd, NEMCLASS_IOC_READ, &rw)) { perror("READ"); ret = 1; }
		else {
			printf("read %llu/%llu bytes:\n",
			       (unsigned long long)rw.done, (unsigned long long)len);
			for (uint64_t i = 0; i < rw.done; i++)
				printf("%02x%s", buf[i], (i % 16 == 15) ? "\n" : " ");
			printf("\n");
			if (rw.done >= 8)
				printf("as u64[0]=0x%016llx\n",
				       (unsigned long long)*(uint64_t *)buf);
		}
		free(buf);
	} else if (!strcmp(cmd, "write") && argc == 6) {
		struct nemclass_rw rw = {0};
		int pid = atoi(argv[3]);
		uint64_t addr = strtoull(argv[4], NULL, 16);
		uint8_t buf[256];
		uint32_t len = 0;

		if (hexstr_to_bytes(argv[5], buf, sizeof(buf), &len)) {
			fprintf(stderr, "bad hexbytes\n"); ret = 1; goto out;
		}
		rw.pid = pid; rw.addr = addr; rw.len = len;
		rw.ubuf = (uint64_t)(uintptr_t)buf;
		if (ioctl(fd, NEMCLASS_IOC_WRITE, &rw)) { perror("WRITE"); ret = 1; }
		else printf("wrote %llu/%u bytes\n", (unsigned long long)rw.done, len);
	} else if (!strcmp(cmd, "regions") && argc == 4) {
		struct nemclass_enum_regions req = {0};
		int pid = atoi(argv[3]);
		uint32_t cap = 4096;
		struct nemclass_region *regs = calloc(cap, sizeof(*regs));

		req.pid = pid; req.max = cap;
		req.ubuf = (uint64_t)(uintptr_t)regs;
		if (ioctl(fd, NEMCLASS_IOC_ENUM_REGIONS, &req)) { perror("ENUM_REGIONS"); ret = 1; }
		else {
			printf("regions: %u shown / %u total\n", req.count, req.total);
			for (uint32_t i = 0; i < req.count; i++)
				printf("  %016llx-%016llx %c%c%c off=0x%llx\n",
				       (unsigned long long)regs[i].start,
				       (unsigned long long)regs[i].end,
				       (regs[i].prot & 1) ? 'r' : '-',
				       (regs[i].prot & 2) ? 'w' : '-',
				       (regs[i].prot & 4) ? 'x' : '-',
				       (unsigned long long)regs[i].file_off);
		}
		free(regs);
	} else if (!strcmp(cmd, "watch") && (argc == 6 || argc == 7)) {
		struct nemclass_bp_set bp = {0};
		uint32_t type = NEMCLASS_BP_W;

		if (argc == 7 && bp_type_of(argv[6], &type)) {
			fprintf(stderr, "bad type\n"); ret = 1; goto out;
		}
		bp.pid = atoi(argv[3]);
		bp.addr = strtoull(argv[4], NULL, 16);
		bp.len = (uint32_t)strtoul(argv[5], NULL, 0);
		bp.kind = NEMCLASS_BP_KIND_HW;
		bp.type = type;
		ret = stream_breakpoint(fd, &bp) ? 1 : 0;
	} else if (!strcmp(cmd, "uprobe") && argc == 5) {
		struct nemclass_bp_set bp = {0};

		bp.pid = atoi(argv[3]);
		bp.addr = strtoull(argv[4], NULL, 16);
		bp.kind = NEMCLASS_BP_KIND_UPROBE;
		ret = stream_breakpoint(fd, &bp) ? 1 : 0;
	} else if (!strcmp(cmd, "ptrace") && argc == 4) {
		struct nemclass_ptrace p = {0};

		p.pid = atoi(argv[3]);
		if (ioctl(fd, NEMCLASS_IOC_PTRACE_QUERY, &p)) { perror("PTRACE_QUERY"); ret = 1; }
		else printf("pid=%d traced=%u tracer_pid=%d\n", p.pid, p.traced, p.tracer_pid);
	} else if (!strcmp(cmd, "hide") && argc == 4) {
		struct nemclass_ptrace p = {0};

		p.pid = atoi(argv[3]);
		if (ioctl(fd, NEMCLASS_IOC_PTRACE_HIDE, &p)) { perror("PTRACE_HIDE"); ret = 1; }
		else printf("hide requested for pid=%d\n", p.pid);
	} else {
		fprintf(stderr, "unknown/malformed command: %s\n", cmd);
		ret = 2;
	}

out:
	close(fd);
	return ret;
}
