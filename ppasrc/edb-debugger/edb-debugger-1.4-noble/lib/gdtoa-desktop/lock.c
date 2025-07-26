#include <stdio.h>
#include <string.h>
#include <pthread.h>

static pthread_mutex_t mutexes[2]={PTHREAD_MUTEX_INITIALIZER,PTHREAD_MUTEX_INITIALIZER};

void ACQUIRE_DTOA_LOCK(unsigned n)
{
    const int err=pthread_mutex_lock(&mutexes[n]);
    if(err) fprintf(stderr, "ACQUIRE_DTOA_LOCK: %s",strerror(err));
}

void FREE_DTOA_LOCK(unsigned n)
{
    const int err=pthread_mutex_unlock(&mutexes[n]);
    if(err) fprintf(stderr, "FREE_DTOA_LOCK: %s",strerror(err));
}

unsigned int dtoa_get_threadno()
{
    return 0; // FIXME: stub, but should work
}
