/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define SOCK_IP_MARK_PORT 39807

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

#ifndef DNS_CAPTURE_PORT
#define DNS_CAPTURE_PORT 15053
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

#ifndef DNS_CAPTURE_PORT
#define DNS_CAPTURE_PORT 0 // todo fix me
#endif

#else
#error "Mesh mode not supported yet"
#endif
