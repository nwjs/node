#ifndef _NW_NODE_INTERFACE_H
#define _NW_NODE_INTERFACE_H

#include "v8/include/v8.h"

namespace node {
extern v8::Persistent<v8::Context> g_context;

// Forward declaration
class Environment;
extern Environment* g_env;

int EmitExit(Environment* env);
void RunAtExit(Environment* env);
void OnMessage(v8::Handle<v8::Message> message, v8::Handle<v8::Value> error);
v8::Handle<v8::Value> CallTickCallback(Environment* env, const v8::Handle<v8::Value> ret);

extern  void SetupUv(int argc, char **argv);
extern  void SetupContext(int argc, char *argv[], v8::Handle<v8::Context> ctx);
extern  void Shutdown();
extern  int Start(int argc, char *argv[]);
}

#endif
