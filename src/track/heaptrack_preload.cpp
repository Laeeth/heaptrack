/*
 * Copyright 2014-2017 Milian Wolff <mail@milianw.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "libheaptrack.h"
#include "util/config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>

#include <atomic>
#include <type_traits>
#include <unordered_set>
#include <mutex>

using namespace std;

#if defined(_ISOC11_SOURCE)
#define HAVE_ALIGNED_ALLOC 1
#else
#define HAVE_ALIGNED_ALLOC 0
#endif

extern "C" {
struct BlkInfo_
{
    void*  base;
    size_t size;
    uint   attr;
};

enum
{
    BLK_ATTR_FINALIZE = 0x01
};

void *gc_malloc(size_t sz, uint32_t ba = 0, const void *ti = nullptr);
void *gc_calloc(size_t sz, uint32_t ba = 0, const void *ti = nullptr);
BlkInfo_ gc_qalloc(size_t sz, uint32_t ba = 0, const void *ti = nullptr);
void *gc_realloc(void* p, size_t sz, uint32_t ba = 0, const void *ti = nullptr);
size_t gc_extend(void* p, size_t mx, size_t sz, const void *ti = nullptr);
uint32_t gc_setAttr(void* p, uint32_t a);
uint32_t gc_getAttr(void* p);
uint32_t gc_clrAttr(void* p, uint32_t a);
BlkInfo_ gc_query(void* p);
void rt_finalizeFromGC(void* p, size_t size, uint32_t attr);
}

namespace {

namespace hooks {

template <typename Signature, typename Base>
struct hook
{
    Signature original = nullptr;

    void init() noexcept
    {
        auto ret = dlsym(RTLD_NEXT, Base::identifier);
        if (!ret) {
            fprintf(stderr, "Could not find original function %s\n", Base::identifier);
            abort();
        }
        original = reinterpret_cast<Signature>(ret);
    }

    template <typename... Args>
    auto operator()(Args... args) const noexcept -> decltype(original(args...))
    {
        return original(args...);
    }

    explicit operator bool() const noexcept
    {
        return original;
    }
};

#define HOOK(name)                                                                                                     \
    struct name##_t : public hook<decltype(&::name), name##_t>                                                         \
    {                                                                                                                  \
        static constexpr const char* identifier = #name;                                                               \
    } name

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"

HOOK(malloc);
HOOK(free);
HOOK(calloc);
#if HAVE_CFREE
HOOK(cfree);
#endif
HOOK(realloc);
HOOK(posix_memalign);
#if HAVE_VALLOC
HOOK(valloc);
#endif
#if HAVE_ALIGNED_ALLOC
HOOK(aligned_alloc);
#endif
HOOK(dlopen);
HOOK(dlclose);

HOOK(gc_malloc);
HOOK(gc_calloc);
HOOK(gc_qalloc);
HOOK(gc_realloc);
HOOK(gc_extend);
HOOK(rt_finalizeFromGC);
HOOK(gc_setAttr);
HOOK(gc_clrAttr);
HOOK(gc_getAttr);
HOOK(gc_query);

#pragma GCC diagnostic pop
#undef HOOK

/**
 * Dummy implementation, since the call to dlsym from findReal triggers a call
 * to calloc.
 *
 * This is only called at startup and will eventually be replaced by the
 * "proper" calloc implementation.
 */
struct DummyPool
{
    static const constexpr size_t MAX_SIZE = 1024;
    char buf[MAX_SIZE] = {0};
    size_t offset = 0;

    bool isDummyAllocation(void* ptr) noexcept
    {
        return ptr >= buf && ptr < buf + MAX_SIZE;
    }

    void* alloc(size_t num, size_t size) noexcept
    {
        size_t oldOffset = offset;
        offset += num * size;
        if (offset >= MAX_SIZE) {
            fprintf(stderr,
                    "failed to initialize, dummy calloc buf size exhausted: "
                    "%zu requested, %zu available\n",
                    offset, MAX_SIZE);
            abort();
        }
        return buf + oldOffset;
    }
};

DummyPool& dummyPool()
{
    static DummyPool pool;
    return pool;
}

void* dummy_calloc(size_t num, size_t size) noexcept
{
    return dummyPool().alloc(num, size);
}

void init()
{
    // heaptrack_init itself calls calloc via std::mutex/_libpthread_init on FreeBSD
    hooks::calloc.original = &dummy_calloc;
    hooks::calloc.init();
    heaptrack_init(getenv("DUMP_HEAPTRACK_OUTPUT"),
                   [] {
                       hooks::dlopen.init();
                       hooks::dlclose.init();
                       hooks::malloc.init();
                       hooks::free.init();
                       hooks::calloc.init();
#if HAVE_CFREE
                       hooks::cfree.init();
#endif
                       hooks::realloc.init();
                       hooks::posix_memalign.init();
#if HAVE_VALLOC
                       hooks::valloc.init();
#endif
#if HAVE_ALIGNED_ALLOC
                       hooks::aligned_alloc.init();
#endif

                       hooks::gc_malloc.init();
                       hooks::gc_calloc.init();
                       hooks::gc_qalloc.init();
                       hooks::gc_realloc.init();
                       hooks::gc_extend.init();
                       hooks::rt_finalizeFromGC.init();
                       hooks::gc_setAttr.init();
                       hooks::gc_clrAttr.init();
                       hooks::gc_getAttr.init();
                       hooks::gc_query.init();

                       // cleanup environment to prevent tracing of child apps
                       unsetenv("LD_PRELOAD");
                       unsetenv("DUMP_HEAPTRACK_OUTPUT");
                   },
                   nullptr, nullptr);
}
}
}

extern "C" {

/// TODO: memalign, pvalloc, ...?

// NOTE: adding noexcept to C functions is a hard error in clang++
//       (but not even a warning in GCC, even with -Wall)
#if defined(__GNUC__) && !defined(__clang__)
#define LIBC_FUN_ATTRS noexcept
#else
#define LIBC_FUN_ATTRS
#endif

void* malloc(size_t size) LIBC_FUN_ATTRS
{
    if (!hooks::malloc) {
        hooks::init();
    }

    void* ptr = hooks::malloc(size);
    heaptrack_malloc(ptr, size);
    return ptr;
}

void free(void* ptr) LIBC_FUN_ATTRS
{
    if (!hooks::free) {
        hooks::init();
    }

    if (hooks::dummyPool().isDummyAllocation(ptr)) {
        return;
    }

    // call handler before handing over the real free implementation
    // to ensure the ptr is not reused in-between and thus the output
    // stays consistent
    heaptrack_free(ptr);

    hooks::free(ptr);
}

void* realloc(void* ptr, size_t size) LIBC_FUN_ATTRS
{
    if (!hooks::realloc) {
        hooks::init();
    }

    void* ret = hooks::realloc(ptr, size);

    if (ret) {
        heaptrack_realloc(ptr, size, ret);
    }

    return ret;
}

void* calloc(size_t num, size_t size) LIBC_FUN_ATTRS
{
    if (!hooks::calloc) {
        hooks::init();
    }

    void* ret = hooks::calloc(num, size);

    if (ret) {
        heaptrack_malloc(ret, num * size);
    }

    return ret;
}

#if HAVE_CFREE
void cfree(void* ptr) LIBC_FUN_ATTRS
{
    if (!hooks::cfree) {
        hooks::init();
    }

    // call handler before handing over the real free implementation
    // to ensure the ptr is not reused in-between and thus the output
    // stays consistent
    if (ptr) {
        heaptrack_free(ptr);
    }

    hooks::cfree(ptr);
}
#endif

int posix_memalign(void** memptr, size_t alignment, size_t size) LIBC_FUN_ATTRS
{
    if (!hooks::posix_memalign) {
        hooks::init();
    }

    int ret = hooks::posix_memalign(memptr, alignment, size);

    if (!ret) {
        heaptrack_malloc(*memptr, size);
    }

    return ret;
}

#if HAVE_ALIGNED_ALLOC
void* aligned_alloc(size_t alignment, size_t size) LIBC_FUN_ATTRS
{
    if (!hooks::aligned_alloc) {
        hooks::init();
    }

    void* ret = hooks::aligned_alloc(alignment, size);

    if (ret) {
        heaptrack_malloc(ret, size);
    }

    return ret;
}
#endif

#if HAVE_VALLOC
void* valloc(size_t size) LIBC_FUN_ATTRS
{
    if (!hooks::valloc) {
        hooks::init();
    }

    void* ret = hooks::valloc(size);

    if (ret) {
        heaptrack_malloc(ret, size);
    }

    return ret;
}
#endif

void* dlopen(const char* filename, int flag) LIBC_FUN_ATTRS
{
    if (!hooks::dlopen) {
        hooks::init();
    }

    void* ret = hooks::dlopen(filename, flag);

    if (ret) {
        heaptrack_invalidate_module_cache();
    }

    return ret;
}

int dlclose(void* handle) LIBC_FUN_ATTRS
{
    if (!hooks::dlclose) {
        hooks::init();
    }

    int ret = hooks::dlclose(handle);

    if (!ret) {
        heaptrack_invalidate_module_cache();
    }

    return ret;
}

/*
 * The finalizer bit is set for every allocation on the D GC heap.
 * This makes sure rt_finalizeFromGC is called for every freed pointer.
 * Because the real rt_finalizeFromGC will crash for a pointer without
 * a finalizer, we have to remember the pointers with a real finalizer
 * in pointers_with_finalizer.
 */
static std::unordered_set<void*> pointers_with_finalizer;
static std::mutex pointers_with_finalizer_mutex;

/*
 * The first allocations on the D GC heap uses ProtoGC, which
 * initializes the real GC and forwards the call. This will look like
 * two allocation and has to be handled specially.
 */
static thread_local int gc_recursive = 0;

void *gc_malloc(size_t size, uint32_t ba, const void *ti)
{
    if (!hooks::gc_malloc) {
        hooks::init();
    }

    gc_recursive++;
    void* ptr = hooks::gc_malloc(size, ba, ti);
    gc_recursive--;
    if (gc_recursive) {
        return ptr;
    }

    uint32_t attr = hooks::gc_getAttr(ptr);
    if(attr & BLK_ATTR_FINALIZE) {
        pointers_with_finalizer_mutex.lock();
        pointers_with_finalizer.insert(ptr);
        pointers_with_finalizer_mutex.unlock();
    }
    hooks::gc_setAttr(ptr, BLK_ATTR_FINALIZE);
    heaptrack_malloc(ptr, size);
    return ptr;
}

void *gc_calloc(size_t size, uint32_t ba, const void *ti)
{
    if (!hooks::gc_calloc) {
        hooks::init();
    }

    gc_recursive++;
    void* ptr = hooks::gc_calloc(size, ba, ti);
    gc_recursive--;
    if (gc_recursive) {
        return ptr;
    }

    uint32_t attr = hooks::gc_getAttr(ptr);
    if (attr & BLK_ATTR_FINALIZE) {
        pointers_with_finalizer_mutex.lock();
        pointers_with_finalizer.insert(ptr);
        pointers_with_finalizer_mutex.unlock();
    }
    hooks::gc_setAttr(ptr, BLK_ATTR_FINALIZE);
    heaptrack_malloc(ptr, size);
    return ptr;
}

BlkInfo_ gc_qalloc(size_t size, uint32_t ba, const void *ti)
{
    if (!hooks::gc_qalloc) {
        hooks::init();
    }

    gc_recursive++;
    BlkInfo_ block = hooks::gc_qalloc(size, ba, ti);
    gc_recursive--;
    if(gc_recursive) {
        return block;
    }

    uint32_t attr = hooks::gc_getAttr(block.base);
    if (attr & BLK_ATTR_FINALIZE) {
        pointers_with_finalizer_mutex.lock();
        pointers_with_finalizer.insert(block.base);
        pointers_with_finalizer_mutex.unlock();
    }
    hooks::gc_setAttr(block.base, BLK_ATTR_FINALIZE);
    heaptrack_malloc(block.base, block.size);
    return block;
}

void *gc_realloc(void* p, size_t size, uint32_t ba, const void *ti)
{
    if (!hooks::gc_realloc) {
        hooks::init();
    }

    gc_recursive++;
    void* ret = hooks::gc_realloc(p, size, ba, ti);
    gc_recursive--;
    if (gc_recursive) {
        return ret;
    }

    if (ret) {
        if (ret != p) {
            pointers_with_finalizer_mutex.lock();
            std::unordered_set<void*>::iterator it = pointers_with_finalizer.find(p);
            if (it != pointers_with_finalizer.end()) {
                pointers_with_finalizer.erase(it);
                pointers_with_finalizer.insert(ret);
            }
            pointers_with_finalizer_mutex.unlock();
        }
        heaptrack_realloc(p, size, ret);
    }
    return ret;
}

size_t gc_extend(void* p, size_t mx, size_t sz, const void *ti)
{
    if (!hooks::gc_extend) {
        hooks::init();
    }

    size_t ret = hooks::gc_extend(p, mx, sz, ti);
    if (ret) {
        heaptrack_realloc(p, ret, p);
    }
    return ret;
}

uint32_t gc_setAttr(void* p, uint32_t a)
{
    if (!hooks::gc_setAttr) {
        hooks::init();
    }

    pointers_with_finalizer_mutex.lock();
    bool hasFinalizer = pointers_with_finalizer.find(p) != pointers_with_finalizer.end();
    if (a & BLK_ATTR_FINALIZE) {
        pointers_with_finalizer.insert(p);
    }
    pointers_with_finalizer_mutex.unlock();

    uint32_t r = hooks::gc_setAttr(p, a);
    if (!hasFinalizer) {
        r &= ~BLK_ATTR_FINALIZE;
    }
    return r;
}

uint32_t gc_clrAttr(void* p, uint32_t a)
{
    if (!hooks::gc_clrAttr) {
        hooks::init();
    }

    pointers_with_finalizer_mutex.lock();
    bool hasFinalizer = pointers_with_finalizer.find(p) != pointers_with_finalizer.end();
    if (a & BLK_ATTR_FINALIZE) {
        pointers_with_finalizer.erase(pointers_with_finalizer.find(p));
    }
    pointers_with_finalizer_mutex.unlock();

    uint32_t r = hooks::gc_clrAttr(p, a & ~BLK_ATTR_FINALIZE);
    if (!hasFinalizer) {
        r &= ~BLK_ATTR_FINALIZE;
    }
    return r;
}

uint32_t gc_getAttr(void* p)
{
    if (!hooks::gc_getAttr) {
        hooks::init();
    }

    pointers_with_finalizer_mutex.lock();
    bool hasFinalizer = pointers_with_finalizer.find(p) != pointers_with_finalizer.end();
    pointers_with_finalizer_mutex.unlock();

    uint32_t r = hooks::gc_getAttr(p);
    if (!hasFinalizer) {
        r &= ~BLK_ATTR_FINALIZE;
    }
    return r;
}

BlkInfo_ gc_query(void* p)
{
    if (!hooks::gc_query) {
        hooks::init();
    }

    pointers_with_finalizer_mutex.lock();
    bool hasFinalizer = pointers_with_finalizer.find(p) != pointers_with_finalizer.end();
    pointers_with_finalizer_mutex.unlock();

    BlkInfo_ ret = hooks::gc_query(p);
    if (!hasFinalizer) {
        ret.attr &= ~BLK_ATTR_FINALIZE;
    }
    return ret;
}

void rt_finalizeFromGC(void* p, size_t size, uint32_t attr)
{
    if (!hooks::rt_finalizeFromGC) {
        hooks::init();
    }
    heaptrack_free(p);

    pointers_with_finalizer_mutex.lock();
    std::unordered_set<void*>::iterator it = pointers_with_finalizer.find(p);
    bool hasFinalizer = false;
    if (it != pointers_with_finalizer.end()) {
        pointers_with_finalizer.erase(it);
        hasFinalizer = true;
    }
    pointers_with_finalizer_mutex.unlock();

    if (hasFinalizer) {
        hooks::rt_finalizeFromGC(p, size, attr);
    }
}
}
