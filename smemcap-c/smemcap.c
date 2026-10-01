#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOCK  512
#define CHUNK  65536

static const char ZEROS[BLOCK];

static void put_octal(char *buf, int len, unsigned long long val) {
    buf[--len] = '\0';
    while (len-- > 0) {
        buf[len] = '0' + (val & 7);
        val >>= 3;
    }
}

static void write_header(const char *name, size_t size, unsigned uid) {
    char hdr[BLOCK];
    unsigned sum = 0;
    int i;

    memset(hdr, 0, BLOCK);
    strncpy(hdr, name, 99);
    put_octal(hdr + 100, 8,  0444);
    put_octal(hdr + 108, 8,  uid);
    put_octal(hdr + 116, 8,  0);
    put_octal(hdr + 124, 12, size);
    put_octal(hdr + 136, 12, 0);
    memset(hdr + 148, ' ', 8);
    hdr[156] = '0';
    memcpy(hdr + 257, "ustar\0", 6);
    memcpy(hdr + 263, "00", 2);

    for (i = 0; i < BLOCK; i++) sum += (unsigned char)hdr[i];

    hdr[148] = '0' + ((sum >> 15) & 7);
    hdr[149] = '0' + ((sum >> 12) & 7);
    hdr[150] = '0' + ((sum >>  9) & 7);
    hdr[151] = '0' + ((sum >>  6) & 7);
    hdr[152] = '0' + ((sum >>  3) & 7);
    hdr[153] = '0' + ((sum      ) & 7);
    hdr[154] = '\0';
    hdr[155] = ' ';

    fwrite(hdr, 1, BLOCK, stdout);
}

static char *read_proc(const char *path, size_t *out_size) {
    char *buf = NULL;
    size_t size = 0, cap = 0;
    ssize_t n;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    do {
        if (size == cap) {
            cap = cap ? cap * 2 : CHUNK;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); close(fd); return NULL; }
            buf = tmp;
        }
        n = read(fd, buf + size, cap - size);
        if (n > 0) size += (size_t)n;
    } while (n > 0);

    close(fd);
    if (n < 0) { free(buf); return NULL; }
    *out_size = size;
    return buf;
}

/* Returns 1 if archived, 0 if file not found. */
static int archive(const char *tar_name, const char *path, unsigned uid) {
    size_t size, rem;
    char *data = read_proc(path, &size);
    if (!data) return 0;
    write_header(tar_name, size, uid);
    fwrite(data, 1, size, stdout);
    rem = size % BLOCK;
    if (rem) fwrite(ZEROS, 1, BLOCK - rem, stdout);
    free(data);
    return 1;
}

static void archive_pid_file(const char *pid, const char *file, unsigned uid) {
    char tar_name[128], path[128];
    snprintf(tar_name, sizeof(tar_name), "%s/%s", pid, file);
    snprintf(path,     sizeof(path),     "/proc/%s/%s", pid, file);
    archive(tar_name, path, uid);
}

static int is_pid(const char *s) {
    if (*s < '1' || *s > '9') return 0;
    for (s++; *s; s++)
        if (*s < '0' || *s > '9') return 0;
    return 1;
}

/* Returns 1 if data contains a line starting with needle. */
static int has_line_prefix(const char *data, size_t size, const char *needle, size_t nlen) {
    size_t i;
    if (size < nlen) return 0;
    if (memcmp(data, needle, nlen) == 0) return 1;
    for (i = 1; i + nlen <= size; i++)
        if (data[i-1] == '\n' && memcmp(data+i, needle, nlen) == 0) return 1;
    return 0;
}

/* Archive fdinfo fds that expose DRM GPU memory: drm-total-* (current
 * spec, used by amdgpu, i915 and xe) or the legacy drm-memory-*. */
static void archive_pid_fdinfo(const char *pid, unsigned uid) {
    char dir_path[128], path[512], tar_name[512];
    DIR *dir;
    struct dirent *de;
    size_t size, rem;
    char *data;

    snprintf(dir_path, sizeof(dir_path), "/proc/%s/fdinfo", pid);
    dir = opendir(dir_path);
    if (!dir) return;

    while ((de = readdir(dir))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        snprintf(path, sizeof(path), "/proc/%s/fdinfo/%s", pid, de->d_name);
        data = read_proc(path, &size);
        if (!data) continue;
        if (has_line_prefix(data, size, "drm-total-", 10) ||
                has_line_prefix(data, size, "drm-memory-", 11)) {
            snprintf(tar_name, sizeof(tar_name), "%s/fdinfo/%s", pid, de->d_name);
            write_header(tar_name, size, uid);
            fwrite(data, 1, size, stdout);
            rem = size % BLOCK;
            if (rem) fwrite(ZEROS, 1, BLOCK - rem, stdout);
        }
        free(data);
    }
    closedir(dir);
}

/* Archive AMD sysfs VRAM stats and NVIDIA GPU metadata. */
static void archive_gpu_system(void) {
    static const char * const amd_mem_files[] = {
        "mem_info_vram_total", "mem_info_vram_used",
        "mem_info_gtt_total",  "mem_info_gtt_used",
        "mem_info_vis_vram_total", "mem_info_vis_vram_used",
        NULL
    };
    DIR *dir;
    struct dirent *de;
    char tar_name[512], sys_path[512];
    int i;

    /* DRM cards: AMD VRAM sysfs files (silently absent on non-AMD cards). */
    dir = opendir("/sys/class/drm");
    if (dir) {
        while ((de = readdir(dir))) {
            /* Match card0, card1, … but not card1-DP-1 or renderD128. */
            if (strncmp(de->d_name, "card", 4) != 0) continue;
            if (de->d_name[4] < '0' || de->d_name[4] > '9') continue;
            if (de->d_name[5] != '\0' && de->d_name[5] != '\n' &&
                    !(de->d_name[5] >= '0' && de->d_name[5] <= '9')) continue;
            for (i = 0; amd_mem_files[i]; i++) {
                snprintf(tar_name, sizeof(tar_name),
                         "gpu/drm/%s/%s", de->d_name, amd_mem_files[i]);
                snprintf(sys_path, sizeof(sys_path),
                         "/sys/class/drm/%s/device/%s", de->d_name, amd_mem_files[i]);
                archive(tar_name, sys_path, 0);
            }
        }
        closedir(dir);
    }

    /* NVIDIA: GPU metadata from /proc/driver/nvidia/gpus/. */
    dir = opendir("/proc/driver/nvidia/gpus");
    if (dir) {
        while ((de = readdir(dir))) {
            if (de->d_name[0] == '.') continue;
            snprintf(tar_name, sizeof(tar_name),
                     "gpu/nvidia/gpus/%s/information", de->d_name);
            snprintf(sys_path, sizeof(sys_path),
                     "/proc/driver/nvidia/gpus/%s/information", de->d_name);
            archive(tar_name, sys_path, 0);
        }
        closedir(dir);
    }
}

static __attribute__((noinline)) void archive_pid(const char *pid) {
    char tar_name[128], path[128];
    struct stat st;
    unsigned uid;
    if (strlen(pid) > 7) return; /* Linux PID max is 4194304 — 7 digits */

    snprintf(path, sizeof(path), "/proc/%s", pid);
    uid = (stat(path, &st) == 0) ? (unsigned)st.st_uid : 0;

    snprintf(tar_name, sizeof(tar_name), "%s/smaps", pid);
    snprintf(path,     sizeof(path),     "/proc/%s/smaps", pid);
    if (!archive(tar_name, path, uid)) return; /* process exited */

    archive_pid_file(pid, "smaps_rollup", uid);
    archive_pid_file(pid, "cmdline",      uid);
    archive_pid_file(pid, "stat",         uid);
    archive_pid_file(pid, "status",       uid);
    archive_pid_file(pid, "cgroup",       uid);
    archive_pid_fdinfo(pid, uid);
}

int main(void) {
    DIR *proc;
    struct dirent *de;
    char end[1024];

    archive("meminfo",         "/proc/meminfo",         0);
    archive("version",         "/proc/version",         0);
    archive("swaps",           "/proc/swaps",           0);
    archive("pressure/memory", "/proc/pressure/memory", 0);
    archive_gpu_system();

    proc = opendir("/proc");
    if (!proc) return 1;
    while ((de = readdir(proc)))
        if (is_pid(de->d_name))
            archive_pid(de->d_name);
    closedir(proc);

    memset(end, 0, sizeof(end));
    fwrite(end, 1, sizeof(end), stdout);
    fflush(stdout);
    return 0;
}
