#if 0  //{ pre-defined
#define ra  x1  /* return address */
#define sp  x2  /* stack ptr */
#define gp  x3  /* global ptr */
#define tp  x4  /* thread ptr */
#endif  //}
#define t0  x5
#define t1  x6
#define t2  x7

#define s0  x8
#define s1  x9

#define rv  a0  /* return value */

/* NOTE: THE FIRST ARGUMENT IS arg1, NOT arg0. */
#define arg1  x10  /* same as rv */
#define arg2  x11
#define arg3  x12
#define arg4  x13
#define arg5  x14
#define arg6  x15
