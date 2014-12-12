// Copyright (c) 2012 Intel Corp
// Copyright (c) 2012 The Chromium Authors
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell co
// pies of the Software, and to permit persons to whom the Software is furnished
//  to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in al
// l copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IM
// PLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNES
// S FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
//  OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WH
// ETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "node.h"
#include "v8.h"
#include "object_life_monitor.h"


namespace nw {

using v8::Value;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;

static void GetHiddenValue(const FunctionCallbackInfo<Value>& args) {
  HandleScope scope(args.GetIsolate());
  args.GetReturnValue().Set(args[0]->ToObject()->GetHiddenValue(args[1]->ToString()));
}

static void SetHiddenValue(const FunctionCallbackInfo<Value>& args) {
  args[0]->ToObject()->SetHiddenValue(args[1]->ToString(), args[2]);
  args.GetReturnValue().Set(v8::Undefined(args.GetIsolate()));
}

static void GetConstructorName(const FunctionCallbackInfo<Value>& args) {
  args.GetReturnValue().Set(args[0]->ToObject()->GetConstructorName());
}

static void SetDestructor(const FunctionCallbackInfo<Value>& args) {
  nw::ObjectLifeMonitor::BindTo(args[0]->ToObject(), args[1]);
  args.GetReturnValue().Set(v8::Undefined(args.GetIsolate()));
}

static void GetCreationContext(const FunctionCallbackInfo<Value>& args) {
  v8::EscapableHandleScope handle_scope(args.GetIsolate());
  v8::Local<v8::Context> creation_context = args[0]->ToObject()->
      CreationContext();

  args.GetReturnValue().Set(handle_scope.Escape(creation_context->Global()));
}

static void GetObjectHash(const FunctionCallbackInfo<Value>& args) {
  v8::EscapableHandleScope handle_scope(args.GetIsolate());
  args.GetReturnValue().Set(handle_scope.Escape(v8::Integer::New(args.GetIsolate(),
                                                                 args[0]->ToObject()->GetIdentityHash())));
}

void InitializeV8Util(v8::Handle<v8::Object> target,
                      Handle<v8::Value> unused,
                      Handle<v8::Context> context) {
  NODE_SET_METHOD(target, "getHiddenValue", GetHiddenValue);
  NODE_SET_METHOD(target, "setHiddenValue", SetHiddenValue);
  NODE_SET_METHOD(target, "getConstructorName", GetConstructorName);
  NODE_SET_METHOD(target, "setDestructor", SetDestructor);
  NODE_SET_METHOD(target, "getCreationContext", GetCreationContext);
  NODE_SET_METHOD(target, "getObjectHash", GetObjectHash);
}

}  // namespace nw

NODE_MODULE_CONTEXT_AWARE_BUILTIN(v8_util, nw::InitializeV8Util)
