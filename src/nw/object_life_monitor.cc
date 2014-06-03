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

#include "object_life_monitor.h"

namespace nw {

// static
void ObjectLifeMonitor::BindTo(v8::Handle<v8::Object> target,
                               v8::Handle<v8::Value> destructor) {
  target->SetHiddenValue(v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), "destructor"), destructor);

  ObjectLifeMonitor* olm = new ObjectLifeMonitor();
  olm->handle_.Reset(target->CreationContext()->GetIsolate(), target);
  olm->handle_.SetWeak(olm, WeakCallback);
}

ObjectLifeMonitor::ObjectLifeMonitor() {
}

ObjectLifeMonitor::~ObjectLifeMonitor() {
  handle_.ClearWeak();
  handle_.Reset();
}

// static
void ObjectLifeMonitor::WeakCallback(
    const v8::WeakCallbackData<v8::Object, ObjectLifeMonitor>& data) {

  ObjectLifeMonitor* olm = data.GetParameter();
  // destructor.call(object, object);
  {
    v8::Isolate* isolate = data.GetIsolate();
    v8::HandleScope scope(isolate);

    v8::Local<v8::Object> obj = v8::Local<v8::Object>::New(isolate, olm->handle_);
    // v8::Local<v8::Object> obj = val->ToObject();
    v8::Local<v8::Value> args[] = { obj };
    v8::Local<v8::Function>::Cast(obj->GetHiddenValue(
                                                      v8::String::NewFromUtf8(isolate, "destructor")))->Call(obj, 1, args);
  }

  delete olm;
}

}  // namespace nw
