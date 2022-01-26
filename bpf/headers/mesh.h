#define ISTIO 1
#define LINKERD 2

#ifndef MESH
#define MESH 1
#endif

#if MESH == ISTIO

#ifndef OUT_REDIRECT_PORT
#define OUT_REDIRECT_PORT 15001
#endif

#ifndef IN_REDIRECT_PORT
#define IN_REDIRECT_PORT 15006
#endif

#ifndef SIDECAR_USER_ID
#define SIDECAR_USER_ID 1337
#endif

#elif MESH == LINKERD

#ifndef OUT_REDIRECT_PORT
#define OUT_REDIRECT_PORT 4140
#endif

#ifndef IN_REDIRECT_PORT
#define IN_REDIRECT_PORT 4143
#endif

#ifndef SIDECAR_USER_ID
#define SIDECAR_USER_ID 2102
#endif

#else
#error "Mesh mode not supported yet"
#endif
