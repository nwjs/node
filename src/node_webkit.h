#ifndef _NW_NODE_INTERFACE_H
#define _NW_NODE_INTERFACE_H

#if 0

#include "v8.h"
#include "uv.h"

#ifdef _WIN32
# ifndef BUILDING_NODE_EXTENSION
#   define NODE_EXTERN __declspec(dllexport)
# else
#   define NODE_EXTERN __declspec(dllimport)
# endif
#else
# define NODE_EXTERN __attribute__((visibility("default")))
#endif

#ifdef BUILDING_NODE_EXTENSION
# undef BUILDING_V8_SHARED
# undef BUILDING_UV_SHARED
# define USING_V8_SHARED 1
# define USING_UV_SHARED 1
#endif
#ifdef _WIN32
# ifdef BUILDING_NW_NODE
#   define NW_EXTERN __declspec(dllexport)
# else
#   define NW_EXTERN __declspec(dllimport)
# endif
#else
# define NW_EXTERN __attribute__((visibility("default")))
#endif

namespace node {
extern NODE_EXTERN v8::Persistent<v8::Context> g_context;
extern NODE_EXTERN v8::Persistent<v8::Context> g_dom_context;

// Forward declaration
class Environment;
extern NODE_EXTERN Environment* g_env;

extern NW_EXTERN void OnMessage(v8::Handle<v8::Message> message, v8::Handle<v8::Value> error);
extern NW_EXTERN v8::Handle<v8::Value> CallNWTickCallback(Environment* env, const v8::Handle<v8::Value> ret);

extern NW_EXTERN void Shutdown();

extern NODE_EXTERN int (*g_nw_uv_run)(uv_loop_t* loop, uv_run_mode mode);

}

#endif

#include <vector>

typedef struct _msg_pump_context_t {
#if defined(__APPLE__)
  void* embed_thread;

  // Semaphore to wait for main loop in the polling thread.
  void* embed_sem;

  // Dummy handle to make uv's loop not quit.
  void* dummy_uv_handle;
#endif
  void* loop;
  std::vector<void*>* wakeup_events;
  void* wakeup_event;
  void* idle_handle;
  void* delay_timer;
} msg_pump_context_t;

typedef bool (*IsNodeInitializedFn)();
typedef void (*CallTickCallbackFn)(void* env);
typedef v8::Handle<v8::Value> (*NWTickCallback)(void* env, const v8::Handle<v8::Value> ret);
typedef void (*SetupNWNodeFn)(int argc, char **argv);
typedef void (*GetNodeContextFn)(void*);
typedef void (*SetNodeContextFn)(v8::Isolate* isolate, void* ctx);
typedef void (*SetNWTickCallbackFn)(NWTickCallback tick_callback);
typedef void (*StartNWInstanceFn)(int argc, char *argv[], v8::Handle<v8::Context> ctx);
typedef void* (*GetNodeEnvFn)();
typedef void* (*GetCurrentEnvironmentFn)(v8::Handle<v8::Context> context);
typedef int (*EmitExitFn)(void* env);
typedef void (*RunAtExitFn)(void* env);
typedef void (*VoidHookFn)(void*);
typedef void (*VoidIntHookFn)(void*, int);
typedef int (*UVRunFn)(void*, int);
typedef void (*SetUVRunFn)(UVRunFn);
typedef int (*NodeStartFn)(int argc, char *argv[]);
typedef void (*SetBlobPathFn)(const char *path);
typedef void* (*GetPointerFn)();
typedef void (*VoidPtr3Fn)(void*, void*, void*);
typedef void (*VoidVoidFn)();
typedef int (*IntVoidFn)();
#endif
