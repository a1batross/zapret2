#if __ANDROID_API__ < 28

#include "random.h"
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_getrandom

#if defined(__aarch64__)
    #define SYS_getrandom 278

#elif defined(__arm__)
    /* ARM EABI */
    #define SYS_getrandom 384

#elif defined(__x86_64__)
    #define SYS_getrandom 318

#elif defined(__i386__)
    #define SYS_getrandom 355

#else
    #error "Unsupported architecture: SYS_getrandom not defined"
#endif

#endif

ssize_t getrandom(void *ptr, size_t len, unsigned int flags)
{
	return syscall(SYS_getrandom, ptr, len, flags);
}

#endif
