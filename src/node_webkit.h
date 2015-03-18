#ifndef _NW_NODE_INTERFACE_H
#define _NW_NODE_INTERFACE_H

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

// Forward declaration
class Environment;
extern NODE_EXTERN Environment* g_env;

extern NW_EXTERN Environment* GetCurrentEnvironment(v8::Handle<v8::Context> context);
extern NODE_EXTERN int EmitExit(Environment* env);
extern NODE_EXTERN void RunAtExit(Environment* env);
extern NW_EXTERN void OnMessage(v8::Handle<v8::Message> message, v8::Handle<v8::Value> error);
typedef v8::Handle<v8::Value> NWTickCallback(Environment* env, const v8::Handle<v8::Value> ret);
extern NW_EXTERN v8::Handle<v8::Value> CallNWTickCallback(Environment* env, const v8::Handle<v8::Value> ret);
extern NW_EXTERN void SetNWTickCallback(NWTickCallback* tick_callback);

extern NODE_EXTERN v8::Handle<v8::Value> CallTickCallback(Environment* env, const v8::Handle<v8::Value> ret);

extern NW_EXTERN bool is_node_initialized();
extern NW_EXTERN void SetupNWNode(int argc, char **argv);
extern NW_EXTERN void StartNWInstance(int argc, char *argv[], v8::Handle<v8::Context> ctx);
extern NW_EXTERN void Shutdown();
extern NODE_EXTERN int Start(int argc, char *argv[]);

extern NODE_EXTERN int (*g_nw_uv_run)(uv_loop_t* loop, uv_run_mode mode);

}

#endif
