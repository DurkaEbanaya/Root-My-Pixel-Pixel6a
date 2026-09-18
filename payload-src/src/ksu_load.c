/*
 * ksu_load.c — on-device KernelSU-Next loader for the bluejay exploit.
 *
 * Runs as uid 2000 (via Shizuku or adb). Uses the temp_su daemon (kernel
 * context, spawned by the exploit) to perform privileged steps.
 *
 *   --ksu-full <ksud> <log>   patch embedded .ko with the KASLR slide from
 *                             <log>, insmod it (allow_shell=1), then run the
 *                             ksud boot stages so installed zip-modules get
 *                             mounted — no PC and no reboot involved.
 *   --ksu-mount <ksud>        re-run the boot stages only (use after
 *                             installing a new zip-module in this session).
 *
 * Why the patch: the GS101 kernel contains every symbol KSUN imports but
 * does not export them, so stock insmod fails with "Unknown symbol". We
 * rewrite each SHN_UNDEF import into SHN_ABS with the runtime address
 * (link address from the embedded table + current KASLR slide), leaving
 * the kernel nothing to resolve.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ksu_blob.h" /* ksu_ko[] / ksu_ko_len / ksu_ksyms[] / ksu_ksyms_len */

#define PATCHED_KO_PATH "/data/local/tmp/ksu-patched.ko"
#define SH_PATH_X "/system/bin/sh"
#define MANAGER_PKG "com.rifsxd.ksunext"
#define MANAGER_ACTIVITY MANAGER_PKG "/.ui.MainActivity"

struct ksym_entry {
  char name[64];
  uint64_t addr;
};

static int ksu_log(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vfprintf(stderr, fmt, ap);
  va_end(ap);
  return n;
}

/* ---------------------------------------------------------------- helpers */

static int run_shell(const char *cmd);

/* Execute `sh -c cmd` as root through the temp_su daemon by re-invoking
 * this binary as its su client. The daemon concatenates argv with spaces
 * and runs `sh -c "<joined>"`, so the command must arrive as a single
 * quoted word — we wrap it in single quotes (none of our commands use
 * them). */
static int run_root(const char *cmd) {
  char self[512];
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (n <= 0) {
    perror("readlink /proc/self/exe");
    return -1;
  }
  self[n] = 0;
  if (strchr(cmd, '\'')) {
    ksu_log("[-] ksu-full: refusing command with quote: %s\n", cmd);
    return -1;
  }

  /* Already root (e.g. --ksu-full invoked through temp_su): run directly.
   * The daemon socket only accepts UID 2000 / app clients, so looping back
   * through it from a root process fails with EPERM. */
  if (geteuid() == 0) {
    return run_shell(cmd);
  }

  char quoted[1024];
  snprintf(quoted, sizeof(quoted), "'%s'", cmd);

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }
  if (pid == 0) {
    execl(self, self, "sh", "-c", quoted, (char *)NULL);
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static char *read_file_all(const char *path, size_t *out_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return NULL;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    close(fd);
    return NULL;
  }
  char *buf = malloc((size_t)st.st_size);
  if (!buf) {
    close(fd);
    return NULL;
  }
  size_t done = 0;
  while (done < (size_t)st.st_size) {
    ssize_t r = read(fd, buf + done, (size_t)st.st_size - done);
    if (r <= 0) {
      free(buf);
      close(fd);
      return NULL;
    }
    done += (size_t)r;
  }
  close(fd);
  *out_len = done;
  return buf;
}

/* Parse the last "slide=%016llx" occurrence from the exploit log. */
static int parse_slide(const char *log_path, uint64_t *out) {
  size_t len = 0;
  char *buf = read_file_all(log_path, &len);
  if (!buf) {
    ksu_log("[-] ksu-full: cannot read exploit log %s\n", log_path);
    return -1;
  }
  uint64_t slide = 0;
  int found = 0;
  char *p = buf;
  while ((p = strstr(p, "slide=")) != NULL) {
    char *end = NULL;
    unsigned long long v = strtoull(p + 6, &end, 16);
    if (end && end != p + 6 && !isxdigit((unsigned char)*end)) {
      /* full hex number; keep the LAST occurrence (final summary line) */
      slide = (uint64_t)v;
      found = 1;
    }
    p += 6;
  }
  free(buf);
  if (!found || slide == 0) {
    ksu_log("[-] ksu-full: no slide= found in %s (exploit not successful?)\n",
            log_path);
    return -1;
  }
  *out = slide;
  return 0;
}

static int load_ksyms(struct ksym_entry **out, uint32_t *out_count) {
  /* binary layout: u32 count, then per entry: u16 name_len, name bytes
   * (no NUL), u64 link address (little-endian) */
  const unsigned char *p = (const unsigned char *)ksu_ksyms;
  size_t left = ksu_ksyms_len;
  if (left < 4) {
    return -1;
  }
  uint32_t count = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  p += 4;
  left -= 4;
  struct ksym_entry *tab = calloc(count, sizeof(*tab));
  if (!tab) {
    return -1;
  }
  for (uint32_t i = 0; i < count; i++) {
    if (left < 2) {
      goto bad;
    }
    uint16_t name_len = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    p += 2;
    left -= 2;
    if (name_len == 0 || name_len >= sizeof(tab[i].name) || left < (size_t)name_len + 8) {
      goto bad;
    }
    memcpy(tab[i].name, p, name_len);
    tab[i].name[name_len] = 0;
    p += name_len;
    left -= name_len;
    uint64_t a = 0;
    for (int b = 7; b >= 0; b--) {
      a = (a << 8) | p[b];
    }
    p += 8;
    left -= 8;
    tab[i].addr = a;
  }
  *out = tab;
  *out_count = count;
  return 0;
bad:
  free(tab);
  return -1;
}

static const struct ksym_entry *ksym_find(const struct ksym_entry *tab,
                                          uint32_t count, const char *name) {
  for (uint32_t i = 0; i < count; i++) {
    if (strcmp(tab[i].name, name) == 0) {
      return &tab[i];
    }
  }
  return NULL;
}

/* Patch every SHN_UNDEF import into SHN_ABS (link + slide). */
static int patch_ko(const char *out_path, uint64_t slide, int *out_patched,
                    int *out_missing) {
  size_t len = 0;
  unsigned char *buf = malloc(ksu_ko_len);
  if (!buf) {
    return -1;
  }
  memcpy(buf, ksu_ko, ksu_ko_len);
  len = ksu_ko_len;

  if (len < sizeof(Elf64_Ehdr)) {
    goto bad;
  }
  Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_ident[EI_CLASS] != ELFCLASS64 ||
      eh->e_ident[EI_DATA] != ELFDATA2LSB || eh->e_type != ET_REL ||
      eh->e_machine != EM_AARCH64) {
    ksu_log("[-] ksu-full: embedded blob is not an arm64 relocatable ELF\n");
    goto bad;
  }
  if (eh->e_shoff == 0 || eh->e_shentsize != sizeof(Elf64_Shdr) ||
      (size_t)eh->e_shoff + (size_t)eh->e_shentsize * eh->e_shnum > len) {
    goto bad;
  }
  Elf64_Shdr *shdrs = (Elf64_Shdr *)(buf + eh->e_shoff);

  Elf64_Shdr *symtab = NULL;
  for (int i = 0; i < eh->e_shnum; i++) {
    if (shdrs[i].sh_type == SHT_SYMTAB) {
      symtab = &shdrs[i];
      break;
    }
  }
  if (!symtab || symtab->sh_link >= eh->e_shnum) {
    ksu_log("[-] ksu-full: no symtab in module\n");
    goto bad;
  }
  Elf64_Shdr *strtab = &shdrs[symtab->sh_link];
  if ((size_t)symtab->sh_offset + symtab->sh_size > len ||
      (size_t)strtab->sh_offset + strtab->sh_size > len) {
    goto bad;
  }

  struct ksym_entry *tab = NULL;
  uint32_t tab_count = 0;
  if (load_ksyms(&tab, &tab_count) != 0) {
    ksu_log("[-] ksu-full: embedded ksym table corrupt\n");
    goto bad;
  }

  size_t sym_count = symtab->sh_size / sizeof(Elf64_Sym);
  Elf64_Sym *syms = (Elf64_Sym *)(buf + symtab->sh_offset);
  const char *strs = (const char *)(buf + strtab->sh_offset);
  int patched = 0, missing = 0;

  for (size_t i = 0; i < sym_count; i++) {
    Elf64_Sym *sym = &syms[i];
    if (sym->st_shndx != SHN_UNDEF || sym->st_name == 0) {
      continue;
    }
    if (sym->st_name >= strtab->sh_size) {
      continue;
    }
    const char *name = strs + sym->st_name;
    const struct ksym_entry *e = ksym_find(tab, tab_count, name);
    if (!e) {
      if (missing < 5) {
        ksu_log("[-] ksu-full: symbol not in table: %s\n", name);
      }
      missing++;
      continue;
    }
    sym->st_value = e->addr + slide;
    sym->st_shndx = SHN_ABS;
    patched++;
  }
  free(tab);

  if (missing != 0) {
    ksu_log("[-] ksu-full: %d unresolved imports, refusing to write\n",
            missing);
    free(buf);
    return -1;
  }

  int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    perror("open patched ko");
    free(buf);
    return -1;
  }
  size_t done = 0;
  while (done < len) {
    ssize_t w = write(fd, buf + done, len - done);
    if (w <= 0) {
      close(fd);
      free(buf);
      return -1;
    }
    done += (size_t)w;
  }
  close(fd);
  free(buf);
  *out_patched = patched;
  *out_missing = missing;
  return 0;
bad:
  free(buf);
  return -1;
}

/* Run `sh -c cmd` as the CURRENT uid (no daemon involved). Used after the
 * KSU module is live: the daemon socket is blocked once KSUN re-enables
 * SELinux enforcing, but `ksud debug su` grants shell root because the
 * module was insmod'ed with allow_shell=1. */
static int run_shell(const char *cmd) {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }
  if (pid == 0) {
    execl(SH_PATH_X, "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Check /proc/modules directly from this process (no child sh). A child
 * grep can be blocked by SELinux once KSUN re-enables enforcing while our
 * process still carries the kernel:s0 context; direct reads of procfs
 * succeeded in live testing from both kernel:s0 (permissive) and ksu:s0. */
static int kernelsu_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  int found = 0;
  for (;;) {
    ssize_t r = read(fd, buf, sizeof(buf));
    if (r <= 0) {
      break;
    }
    for (ssize_t i = 0; i + 8 <= r; i++) {
      if (memcmp(buf + i, "kernelsu", 8) == 0) {
        found = 1;
        break;
      }
    }
    if (found) {
      break;
    }
  }
  close(fd);
  return found;
}

/* Run one ksud stage (stages are idempotent in ksud, just execute them). */
static int run_stage_direct(const char *ksud, const char *stage) {
  char cmd[600];
  snprintf(cmd, sizeof(cmd), "%s %s", ksud, stage);
  return run_shell(cmd);
}

int ksu_full_main(int argc, char **argv) {
  (void)argc;
  const char *ksud = argc >= 3 ? argv[2] : "/data/local/tmp/ksud";
  const char *log = argc >= 4 ? argv[3] : "/data/local/tmp/exploit.log";
  int rc = 0;
  (void)ksud;

  uint64_t slide = 0;
  if (parse_slide(log, &slide) != 0) {
    return 2;
  }
  ksu_log("[+] ksu-full: slide=%llx\n", (unsigned long long)slide);

  int patched = 0, missing = 0;
  if (patch_ko(PATCHED_KO_PATH, slide, &patched, &missing) != 0) {
    return 3;
  }
  ksu_log("[+] ksu-full: patched %d imports -> %s\n", patched,
          PATCHED_KO_PATH);

  if (kernelsu_loaded()) {
    ksu_log("[+] ksu-full: kernelsu already loaded, skipping insmod\n");
    return 0;
  }

  /* Load the module with a DIRECT init_module(2) syscall from THIS process
   * (no /system/bin/insmod, no sh child). KSUN's late-load init path runs
   * escape_to_root_for_init() on `current` — the process executing the
   * module init — BEFORE it flips enforcing. So after the syscall returns
   * THIS helper is already uid0 in u:r:ksu:s0 and can still exec binaries
   * under /data, which neither kernel:s0 nor untrusted_app can do under
   * enforcing. A `sh -c insmod` child would receive the escape instead and
   * this process would stay kernel:s0 (validated: it lost all exec on
   * /data after insmod). */
  size_t ko_len = 0;
  unsigned char *ko_img = NULL;
  int kfd = open(PATCHED_KO_PATH, O_RDONLY);
  if (kfd < 0) {
    ksu_log("[-] ksu-full: cannot read %s\n", PATCHED_KO_PATH);
    return 4;
  }
  struct stat kst;
  if (fstat(kfd, &kst) != 0 || kst.st_size <= 0) {
    close(kfd);
    ksu_log("[-] ksu-full: stat %s failed\n", PATCHED_KO_PATH);
    return 4;
  }
  ko_len = (size_t)kst.st_size;
  ko_img = malloc(ko_len);
  if (!ko_img) {
    close(kfd);
    return 4;
  }
  size_t kdone = 0;
  while (kdone < ko_len) {
    ssize_t k = read(kfd, ko_img + kdone, ko_len - kdone);
    if (k <= 0) {
      close(kfd);
      free(ko_img);
      return 4;
    }
    kdone += (size_t)k;
  }
  close(kfd);

  if (syscall(__NR_init_module, ko_img, ko_len, "allow_shell=1") != 0) {
    /* EEXIST means the module is already live (retry loop). Anything else
     * is a real failure; no staged mount must be attempted either way
     * before the module UAPI exists (ksud would silently skip: "UAPI
     * version mismatch: kernel=0"). */
    int e = errno;
    free(ko_img);
    if (e != EEXIST) {
      ksu_log("[-] ksu-full: init_module failed: %s\n", strerror(e));
      return 4;
    }
    ksu_log("[*] ksu-full: module already loaded (EEXIST)\n");
  } else {
    free(ko_img);
    ksu_log("[+] ksu-full: init_module ok — helper escaped to KSU domain\n");
  }

  /* THIS process now holds u:r:ksu:s0 (escape happened inside init_module).
   * ksud stages COULD NOT run before the module was loaded (UAPI probe
   * returned kernel=0 and ksud skipped on_post_data_fs with rc=0 — a false
   * success). Run the canonical mount pipeline now, from the escaped
   * process, with a double-stack guard. /data/adb/ksud is deployed by
   * prepareAssets()/earlier ksud runs; fall back to /data/local/tmp.
   * ALSO: enter PID 1's mount namespace first. The temp_su daemon lives in
   * a SLAVE mount ns (master:1): mounts made there stay invisible to the
   * system (validated live — overlay existed only in the daemon's ns).
   * PID 1's ns is shared:1, so mounts from there propagate everywhere. */
  int nsfd = open("/proc/1/ns/mnt", O_RDONLY);
  if (nsfd >= 0) {
    if (setns(nsfd, CLONE_NEWNS) != 0) {
      ksu_log("[*] ksu-full: setns(PID1 mnt) failed: %s\n", strerror(errno));
    } else {
      ksu_log("[*] ksu-full: entered PID1 mount ns\n");
    }
    close(nsfd);
  }
  const char *ksud_paths[] = {"/data/adb/ksud", ksud};
  for (int i = 0; i < 2; i++) {
    struct stat sst;
    if (stat(ksud_paths[i], &sst) != 0 || !(sst.st_mode & S_IXUSR)) {
      continue;
    }
    char mcmd[600];
    snprintf(mcmd, sizeof(mcmd),
             "grep -q \"overlay KSU\" /proc/1/mountinfo || %s post-fs-data",
             ksud_paths[i]);
    int mrc = run_shell(mcmd);
    ksu_log("[*] ksu-full: post-fs-data rc=%d\n", mrc);
    /* The remaining boot stages run module service.sh / boot-completed.sh
     * scripts, load module sepolicy.rules and system.prop — needed by any
     * module that is more than plain file replacement. Run them from this
     * same ksu:s0 + PID1-ns context (non-blocking on the KSU boot flow;
     * we block because the caller wants a definitive result). */
    int src1 = run_stage_direct(ksud_paths[i], "services");
    ksu_log("[*] ksu-full: services rc=%d\n", src1);
    int src2 = run_stage_direct(ksud_paths[i], "boot-completed");
    ksu_log("[*] ksu-full: boot-completed rc=%d\n", src2);
    rc |= (src1 != 0) | (src2 != 0 ? 2 : 0);
    break;
  }
  ksu_log("[+] ksu-full: SUCCESS — KernelSU-Next is live\n");
  return rc;
}


int ksu_mount_main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  /* Stage replay must run from a KSU-flagged process (UID 2000/app via
   * `ksud debug su`), not from kernel:s0 — see ksu_full_main. The caller
   * (keeper_apk.sh) runs the stages itself. */
  ksu_log("[-] ksu-mount: stages are run by the caller via ksud debug su\n");
  return 0;
}
