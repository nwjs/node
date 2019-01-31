// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "node_binding.h"
#include "node_buffer.h"
#include "node_constants.h"
#include "node_context_data.h"
#include "node_errors.h"
#include "node_internals.h"
#include "node_metadata.h"
#include "node_native_module.h"
#include "node_options-inl.h"
#include "node_perf.h"
#include "node_platform.h"
#include "node_process.h"
#include "node_revert.h"
#include "node_version.h"
#include "tracing/traced_value.h"

#include <iostream>

#include <vector>
#include "node_webkit.h"

#if HAVE_OPENSSL
#include "node_crypto.h"
#endif

#if defined(NODE_HAVE_I18N_SUPPORT)
#include "node_i18n.h"
#include <unicode/udata.h>
#endif

#if HAVE_INSPECTOR
#include "inspector_io.h"
#endif

#if defined HAVE_DTRACE || defined HAVE_ETW
#include "node_dtrace.h"
#endif

#include "async_wrap-inl.h"
#include "env-inl.h"
#include "handle_wrap.h"
#include "req_wrap-inl.h"
#include "string_bytes.h"
#include "tracing/agent.h"
#include "tracing/node_trace_writer.h"
#include "util.h"
#include "uv.h"
#if NODE_USE_V8_PLATFORM
#include "libplatform/libplatform.h"
#endif  // NODE_USE_V8_PLATFORM
#include "v8-profiler.h"

#ifdef NODE_ENABLE_VTUNE_PROFILING
#include "../deps/v8/src/third_party/vtune/v8-vtune.h"
#endif

#ifdef NODE_ENABLE_LARGE_CODE_PAGES
#include "large_pages/node_large_page.h"
#endif

#include <errno.h>
#include <fcntl.h>  // _O_RDWR
#include <limits.h>  // PATH_MAX
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <string>
#include <vector>

#if defined(NODE_HAVE_I18N_SUPPORT)
#include <unicode/uvernum.h>
#endif

#ifdef NODE_REPORT
#include "node_report.h"
#endif

#if defined(LEAK_SANITIZER)
#include <sanitizer/lsan_interface.h>
#endif

#if defined(_MSC_VER)
#include <direct.h>
#include <io.h>
#else
#include <pthread.h>
#include <sys/resource.h>  // getrlimit, setrlimit
#include <unistd.h>        // STDIN_FILENO, STDERR_FILENO
#endif

extern "C" {
NODE_EXTERN void* g_get_node_env();
}

namespace node {

using options_parser::kAllowedInEnvironment;
using options_parser::kDisallowedInEnvironment;
using v8::Array;
using v8::Boolean;
using v8::Context;
using v8::DEFAULT;
using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::HandleScope;
using v8::Int32;
using v8::Integer;
using v8::Isolate;
using v8::Just;
using v8::Local;
using v8::Locker;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Message;
using v8::MicrotasksPolicy;
using v8::Object;
using v8::ObjectTemplate;
using v8::Script;
using v8::ScriptOrigin;
using v8::SealHandleScope;
using v8::String;
using v8::TracingController;
using v8::Undefined;
using v8::V8;
using v8::Value;

NODE_EXTERN v8::Persistent<Context> g_context;
NODE_EXTERN v8::Persistent<Context> g_dom_context;
static UVRunFn g_nw_uv_run = nullptr;
static NWTickCallback g_nw_tick_callback = nullptr;
static const char* g_native_blob_path = nullptr;
bool node_is_nwjs = false;

namespace per_process {
// Tells whether --prof is passed.
// TODO(joyeecheung): move env->options()->prof_process to
// per_process::cli_options.prof_process and use that instead.
static bool v8_is_profiling = false;
static node_module* modpending;

// TODO(joyeecheung): these are no longer necessary. Remove them.
// See: https://github.com/nodejs/node/pull/25302#discussion_r244924196
// Isolate on the main thread
static Mutex main_isolate_mutex;
static Isolate* main_isolate;

// node_revert.h
// Bit flag used to track security reverts.
unsigned int reverted_cve = 0;

// util.h
// Tells whether the per-process V8::Initialize() is called and
// if it is safe to call v8::Isolate::GetCurrent().
bool v8_initialized = false;

// node_internals.h
// process-relative uptime base, initialized at start-up
double prog_start_time;
}  // namespace per_process

#if 0
// Ensures that __metadata trace events are only emitted
// when tracing is enabled.
class NodeTraceStateObserver :
    public TracingController::TraceStateObserver {
 public:
  void OnTraceEnabled() override {
    char name_buffer[512];
    if (uv_get_process_title(name_buffer, sizeof(name_buffer)) == 0) {
      // Only emit the metadata event if the title can be retrieved
      // successfully. Ignore it otherwise.
      TRACE_EVENT_METADATA1("__metadata", "process_name",
                            "name", TRACE_STR_COPY(name_buffer));
    }
    TRACE_EVENT_METADATA1("__metadata",
                          "version",
                          "node",
                          per_process::metadata.versions.node.c_str());
    TRACE_EVENT_METADATA1("__metadata", "thread_name",
                          "name", "JavaScriptMainThread");

    auto trace_process = tracing::TracedValue::Create();
    trace_process->BeginDictionary("versions");

#define V(key)                                                                 \
  trace_process->SetString(#key, per_process::metadata.versions.key.c_str());

    NODE_VERSIONS_KEYS(V)
#undef V

    trace_process->EndDictionary();

    trace_process->SetString("arch", per_process::metadata.arch.c_str());
    trace_process->SetString("platform",
                             per_process::metadata.platform.c_str());

    trace_process->BeginDictionary("release");
    trace_process->SetString("name",
                             per_process::metadata.release.name.c_str());
#if NODE_VERSION_IS_LTS
    trace_process->SetString("lts", per_process::metadata.release.lts.c_str());
#endif
    trace_process->EndDictionary();
    TRACE_EVENT_METADATA1("__metadata", "node",
                          "process", std::move(trace_process));

    // This only runs the first time tracing is enabled
    controller_->RemoveTraceStateObserver(this);
  }

  void OnTraceDisabled() override {
    // Do nothing here. This should never be called because the
    // observer removes itself when OnTraceEnabled() is called.
    UNREACHABLE();
  }

  explicit NodeTraceStateObserver(TracingController* controller) :
      controller_(controller) {}
  ~NodeTraceStateObserver() override {}

 private:
  TracingController* controller_;
};

#endif

static struct {
#if NODE_USE_V8_PLATFORM
  void Initialize(int thread_pool_size) {
      tracing_agent_.reset(nullptr);
      platform_ = new NodePlatform(thread_pool_size, new v8::TracingController());
      V8::InitializePlatform(platform_);
      //      tracing::TraceEventHelper::SetTracingController(
      //  new v8::TracingController());
      //    }
  }

  void Dispose() {
    StopTracingAgent();
    platform_->Shutdown();
    delete platform_;
    platform_ = nullptr;
    // Destroy tracing after the platform (and platform threads) have been
    // stopped.
    tracing_agent_.reset(nullptr);
    //trace_state_observer_.reset(nullptr);
  }

  void DrainVMTasks(Isolate* isolate) {
    platform_->DrainTasks(isolate);
  }

  void CancelVMTasks(Isolate* isolate) {
    platform_->CancelPendingDelayedTasks(isolate);
  }

  void StartTracingAgent() {
#if 0
    if (per_process::cli_options->trace_event_categories.empty()) {
      tracing_file_writer_ = tracing_agent_->DefaultHandle();
    } else {
      std::vector<std::string> categories =
          SplitString(per_process::cli_options->trace_event_categories, ',');

      tracing_file_writer_ = tracing_agent_->AddClient(
          std::set<std::string>(std::make_move_iterator(categories.begin()),
                                std::make_move_iterator(categories.end())),
          std::unique_ptr<tracing::AsyncTraceWriter>(
              new tracing::NodeTraceWriter(
                  per_process::cli_options->trace_event_file_pattern)),
          tracing::Agent::kUseDefaultCategories);
    }
#endif
  }

  void StopTracingAgent() {
#if 0
    tracing_file_writer_.reset();
#endif
  }

  tracing::AgentWriterHandle* GetTracingAgentWriter() {
    return &tracing_file_writer_;
  }

  NodePlatform* Platform() {
    return platform_;
  }

  //std::unique_ptr<NodeTraceStateObserver> trace_state_observer_;
  std::unique_ptr<tracing::Agent> tracing_agent_;
  tracing::AgentWriterHandle tracing_file_writer_;
  NodePlatform* platform_;
#else  // !NODE_USE_V8_PLATFORM
  void Initialize(int thread_pool_size) {}
  void Dispose() {}
  void DrainVMTasks(Isolate* isolate) {}
  void CancelVMTasks(Isolate* isolate) {}

  void StartTracingAgent() {
    if (!trace_enabled_categories.empty()) {
      fprintf(stderr, "Node compiled with NODE_USE_V8_PLATFORM=0, "
                      "so event tracing is not available.\n");
    }
  }
  void StopTracingAgent() {}

  tracing::AgentWriterHandle* GetTracingAgentWriter() {
    return nullptr;
  }

  NodePlatform* Platform() {
    return nullptr;
  }
#endif  // !NODE_USE_V8_PLATFORM
} v8_platform;

tracing::AgentWriterHandle* GetTracingAgentWriter() {
  return v8_platform.GetTracingAgentWriter();
}

void DisposePlatform() {
  v8_platform.Dispose();
}

#ifdef __POSIX__
static const unsigned kMaxSignal = 32;
#endif

const char* signo_string(int signo) {
#define SIGNO_CASE(e)  case e: return #e;
  switch (signo) {
#ifdef SIGHUP
  SIGNO_CASE(SIGHUP);
#endif

#ifdef SIGINT
  SIGNO_CASE(SIGINT);
#endif

#ifdef SIGQUIT
  SIGNO_CASE(SIGQUIT);
#endif

#ifdef SIGILL
  SIGNO_CASE(SIGILL);
#endif

#ifdef SIGTRAP
  SIGNO_CASE(SIGTRAP);
#endif

#ifdef SIGABRT
  SIGNO_CASE(SIGABRT);
#endif

#ifdef SIGIOT
# if SIGABRT != SIGIOT
  SIGNO_CASE(SIGIOT);
# endif
#endif

#ifdef SIGBUS
  SIGNO_CASE(SIGBUS);
#endif

#ifdef SIGFPE
  SIGNO_CASE(SIGFPE);
#endif

#ifdef SIGKILL
  SIGNO_CASE(SIGKILL);
#endif

#ifdef SIGUSR1
  SIGNO_CASE(SIGUSR1);
#endif

#ifdef SIGSEGV
  SIGNO_CASE(SIGSEGV);
#endif

#ifdef SIGUSR2
  SIGNO_CASE(SIGUSR2);
#endif

#ifdef SIGPIPE
  SIGNO_CASE(SIGPIPE);
#endif

#ifdef SIGALRM
  SIGNO_CASE(SIGALRM);
#endif

  SIGNO_CASE(SIGTERM);

#ifdef SIGCHLD
  SIGNO_CASE(SIGCHLD);
#endif

#ifdef SIGSTKFLT
  SIGNO_CASE(SIGSTKFLT);
#endif


#ifdef SIGCONT
  SIGNO_CASE(SIGCONT);
#endif

#ifdef SIGSTOP
  SIGNO_CASE(SIGSTOP);
#endif

#ifdef SIGTSTP
  SIGNO_CASE(SIGTSTP);
#endif

#ifdef SIGBREAK
  SIGNO_CASE(SIGBREAK);
#endif

#ifdef SIGTTIN
  SIGNO_CASE(SIGTTIN);
#endif

#ifdef SIGTTOU
  SIGNO_CASE(SIGTTOU);
#endif

#ifdef SIGURG
  SIGNO_CASE(SIGURG);
#endif

#ifdef SIGXCPU
  SIGNO_CASE(SIGXCPU);
#endif

#ifdef SIGXFSZ
  SIGNO_CASE(SIGXFSZ);
#endif

#ifdef SIGVTALRM
  SIGNO_CASE(SIGVTALRM);
#endif

#ifdef SIGPROF
  SIGNO_CASE(SIGPROF);
#endif

#ifdef SIGWINCH
  SIGNO_CASE(SIGWINCH);
#endif

#ifdef SIGIO
  SIGNO_CASE(SIGIO);
#endif

#ifdef SIGPOLL
# if SIGPOLL != SIGIO
  SIGNO_CASE(SIGPOLL);
# endif
#endif

#ifdef SIGLOST
# if SIGLOST != SIGABRT
  SIGNO_CASE(SIGLOST);
# endif
#endif

#ifdef SIGPWR
# if SIGPWR != SIGLOST
  SIGNO_CASE(SIGPWR);
# endif
#endif

#ifdef SIGINFO
# if !defined(SIGPWR) || SIGINFO != SIGPWR
  SIGNO_CASE(SIGINFO);
# endif
#endif

#ifdef SIGSYS
  SIGNO_CASE(SIGSYS);
#endif

  default: return "";
  }
}

void* ArrayBufferAllocator::Allocate(size_t size) {
  if (zero_fill_field_ || per_process::cli_options->zero_fill_all_buffers)
    return UncheckedCalloc(size);
  else
    return UncheckedMalloc(size);
}

namespace {

#if 0
bool ShouldAbortOnUncaughtException(Isolate* isolate) {
  HandleScope scope(isolate);
  Environment* env = Environment::GetCurrent(isolate);
  return env != nullptr &&
         env->should_abort_on_uncaught_toggle()[0] &&
         !env->inside_should_not_abort_on_uncaught_scope();
}
#endif

}  // anonymous namespace


void AddPromiseHook(Isolate* isolate, promise_hook_func fn, void* arg) {
  Environment* env = Environment::GetCurrent(isolate);
  CHECK_NOT_NULL(env);
  env->AddPromiseHook(fn, arg);
}

void AddEnvironmentCleanupHook(Isolate* isolate,
                               void (*fun)(void* arg),
                               void* arg) {
  Environment* env = Environment::GetCurrent(isolate);
  CHECK_NOT_NULL(env);
  env->AddCleanupHook(fun, arg);
}


void RemoveEnvironmentCleanupHook(Isolate* isolate,
                                  void (*fun)(void* arg),
                                  void* arg) {
  Environment* env = Environment::GetCurrent(isolate);
  CHECK_NOT_NULL(env);
  env->RemoveCleanupHook(fun, arg);
}

static void WaitForInspectorDisconnect(Environment* env) {
#if HAVE_INSPECTOR
  if (env->inspector_agent()->IsActive()) {
    // Restore signal dispositions, the app is done and is no longer
    // capable of handling signals.
#if defined(__POSIX__) && !defined(NODE_SHARED_MODE)
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    for (unsigned nr = 1; nr < kMaxSignal; nr += 1) {
      if (nr == SIGKILL || nr == SIGSTOP || nr == SIGPROF)
        continue;
      act.sa_handler = (nr == SIGPIPE) ? SIG_IGN : SIG_DFL;
      CHECK_EQ(0, sigaction(nr, &act, nullptr));
    }
#endif
    env->inspector_agent()->WaitForDisconnect();
  }
#endif
}

void Exit(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  WaitForInspectorDisconnect(env);
  int code = args[0]->Int32Value(env->context()).FromMaybe(0);
  env->Exit(code);
}

NODE_EXTERN void OnMessage(Local<Message> message, Local<Value> error) {
  Isolate* isolate = message->GetIsolate();
  switch (message->ErrorLevel()) {
    case Isolate::MessageErrorLevel::kMessageWarning: {
      Environment* env = Environment::GetCurrent(isolate);
      if (!env) {
        break;
      }
      Utf8Value filename(isolate,
          message->GetScriptOrigin().ResourceName());
      // (filename):(line) (message)
      std::stringstream warning;
      warning << *filename;
      warning << ":";
      warning << message->GetLineNumber(env->context()).FromMaybe(-1);
      warning << " ";
      v8::String::Utf8Value msg(isolate, message->Get());
      warning << *msg;
      USE(ProcessEmitWarningGeneric(env, warning.str().c_str(), "V8"));
      break;
    }
    case Isolate::MessageErrorLevel::kMessageError:
      FatalException(isolate, error, message);
      break;
  }
}

void SignalExit(int signo) {
  uv_tty_reset_mode();
#ifdef __FreeBSD__
  // FreeBSD has a nasty bug, see RegisterSignalHandler for details
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  CHECK_EQ(sigaction(signo, &sa, nullptr), 0);
#endif
  raise(signo);
}

static MaybeLocal<Value> ExecuteBootstrapper(
    Environment* env,
    const char* id,
    std::vector<Local<String>>* parameters,
    std::vector<Local<Value>>* arguments) {
  MaybeLocal<Value> ret = per_process::native_module_loader.CompileAndCall(
      env->context(), id, parameters, arguments, env);

  // If there was an error during bootstrap then it was either handled by the
  // FatalException handler or it's unrecoverable (e.g. max call stack
  // exceeded). Either way, clear the stack so that the AsyncCallbackScope
  // destructor doesn't fail on the id check.
  // There are only two ways to have a stack size > 1: 1) the user manually
  // called MakeCallback or 2) user awaited during bootstrap, which triggered
  // _tickCallback().
  if (ret.IsEmpty()) {
    env->async_hooks()->clear_async_id_stack();
  }

  return ret;
}

void LoadEnvironment(Environment* env) {
  RunBootstrapping(env);

  // To allow people to extend Node in different ways, this hook allows
  // one to drop a file lib/_third_party_main.js into the build
  // directory which will be executed instead of Node's normal loading.
  if (per_process::native_module_loader.Exists("_third_party_main")) {
    StartExecution(env, "_third_party_main");
  } else {
    // TODO(joyeecheung): create different scripts for different
    // execution modes:
    // - `main_thread_main.js` when env->is_main_thread()
    // - `worker_thread_main.js` when !env->is_main_thread()
    // - `run_third_party_main.js` for `_third_party_main`
    // - `inspect_main.js` for `node inspect`
    // - `mkcodecache_main.js` for the code cache generator
    // - `print_help_main.js` for --help
    // - `bash_completion_main.js` for --completion-bash
    // - `internal/v8_prof_processor` for --prof-process
    // And leave bootstrap/node.js dedicated to the setup of the environment.
    // We may want to move this switch out of LoadEnvironment, especially for
    // the per-process options.
    StartExecution(env, nullptr);
  }
}

void RunBootstrapping(Environment* env) {
  CHECK(!env->has_run_bootstrapping_code());
  env->set_has_run_bootstrapping_code(true);

  HandleScope handle_scope(env->isolate());
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();

  // Add a reference to the global object
  Local<Object> global = context->Global();

#if defined HAVE_DTRACE || defined HAVE_ETW
  InitDTrace(env, global);
#endif

  Local<Object> process = env->process_object();

  // Setting global properties for the bootstrappers to use:
  // - global
  // Expose the global object as a property on itself
  // (Allows you to set stuff on `global` from anywhere in JavaScript.)
  global->Set(context, FIXED_ONE_BYTE_STRING(env->isolate(), "global"), global)
      .FromJust();

  // Create binding loaders
  std::vector<Local<String>> loaders_params = {
      env->process_string(),
      FIXED_ONE_BYTE_STRING(isolate, "getBinding"),
      FIXED_ONE_BYTE_STRING(isolate, "getLinkedBinding"),
      FIXED_ONE_BYTE_STRING(isolate, "getInternalBinding"),
      FIXED_ONE_BYTE_STRING(isolate, "debugBreak")};
  std::vector<Local<Value>> loaders_args = {
      process,
      env->NewFunctionTemplate(binding::GetBinding)
          ->GetFunction(context)
          .ToLocalChecked(),
      env->NewFunctionTemplate(binding::GetLinkedBinding)
          ->GetFunction(context)
          .ToLocalChecked(),
      env->NewFunctionTemplate(binding::GetInternalBinding)
          ->GetFunction(context)
          .ToLocalChecked(),
      Boolean::New(isolate,
                   env->options()->debug_options().break_node_first_line)};

  MaybeLocal<Value> loader_exports;
  // Bootstrap internal loaders
  loader_exports = ExecuteBootstrapper(
      env, "internal/bootstrap/loaders", &loaders_params, &loaders_args);
  if (loader_exports.IsEmpty()) {
    return;
  }

  // process, loaderExports, isMainThread
  std::vector<Local<String>> node_params = {
      env->process_string(),
      FIXED_ONE_BYTE_STRING(isolate, "loaderExports"),
      FIXED_ONE_BYTE_STRING(isolate, "isMainThread")};
  std::vector<Local<Value>> node_args = {
      process,
      loader_exports.ToLocalChecked(),
      Boolean::New(isolate, env->is_main_thread())};

  Local<Value> start_execution;
  if (!ExecuteBootstrapper(
          env, "internal/bootstrap/node", &node_params, &node_args)
          .ToLocal(&start_execution)) {
    return;
  }

  if (start_execution->IsFunction())
    env->set_start_execution_function(start_execution.As<Function>());
}

void StartExecution(Environment* env, const char* main_script_id) {
  HandleScope handle_scope(env->isolate());
  // We have to use Local<>::New because of the optimized way in which we access
  // the object in the env->...() getters, which does not play well with
  // resetting the handle while we're accessing the object through the Local<>.
  Local<Function> start_execution =
      Local<Function>::New(env->isolate(), env->start_execution_function());
  env->set_start_execution_function(Local<Function>());

  if (start_execution.IsEmpty()) return;

  Local<Value> main_script_v;
  if (main_script_id == nullptr) {
    // TODO(joyeecheung): make this mandatory - we may also create an overload
    // for main_script that is a Local<Function>.
    main_script_v = Undefined(env->isolate());
  } else {
    main_script_v = OneByteString(env->isolate(), main_script_id);
  }

  Local<Value> argv[] = {main_script_v};
  USE(start_execution->Call(
      env->context(), Undefined(env->isolate()), arraysize(argv), argv));
}


#ifdef __POSIX__
void RegisterSignalHandler(int signal,
                           void (*handler)(int signal),
                           bool reset_handler) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
#ifndef __FreeBSD__
  // FreeBSD has a nasty bug with SA_RESETHAND reseting the SA_SIGINFO, that is
  // in turn set for a libthr wrapper. This leads to a crash.
  // Work around the issue by manually setting SIG_DFL in the signal handler
  sa.sa_flags = reset_handler ? SA_RESETHAND : 0;
#endif
  sigfillset(&sa.sa_mask);
  CHECK_EQ(sigaction(signal, &sa, nullptr), 0);
}

#endif  // __POSIX__

inline void PlatformInit() {
#ifdef __POSIX__
#if HAVE_INSPECTOR
  sigset_t sigmask;
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGUSR1);
  const int err = pthread_sigmask(SIG_SETMASK, &sigmask, nullptr);
#endif  // HAVE_INSPECTOR

  // Make sure file descriptors 0-2 are valid before we start logging anything.
  for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd += 1) {
    struct stat ignored;
    if (fstat(fd, &ignored) == 0)
      continue;
    // Anything but EBADF means something is seriously wrong.  We don't
    // have to special-case EINTR, fstat() is not interruptible.
    if (errno != EBADF)
      ABORT();
    if (fd != open("/dev/null", O_RDWR))
      ABORT();
  }

#if HAVE_INSPECTOR
  CHECK_EQ(err, 0);
#endif  // HAVE_INSPECTOR

#ifndef NODE_SHARED_MODE
  // Restore signal dispositions, the parent process may have changed them.
  struct sigaction act;
  memset(&act, 0, sizeof(act));

  // The hard-coded upper limit is because NSIG is not very reliable; on Linux,
  // it evaluates to 32, 34 or 64, depending on whether RT signals are enabled.
  // Counting up to SIGRTMIN doesn't work for the same reason.
  for (unsigned nr = 1; nr < kMaxSignal; nr += 1) {
    if (nr == SIGKILL || nr == SIGSTOP)
      continue;
    act.sa_handler = (nr == SIGPIPE) ? SIG_IGN : SIG_DFL;
    CHECK_EQ(0, sigaction(nr, &act, nullptr));
  }
#endif  // !NODE_SHARED_MODE

  RegisterSignalHandler(SIGINT, SignalExit, true);
  RegisterSignalHandler(SIGTERM, SignalExit, true);

  // Raise the open file descriptor limit.
  struct rlimit lim;
  if (getrlimit(RLIMIT_NOFILE, &lim) == 0 && lim.rlim_cur != lim.rlim_max) {
    // Do a binary search for the limit.
    rlim_t min = lim.rlim_cur;
    rlim_t max = 1 << 20;
    // But if there's a defined upper bound, don't search, just set it.
    if (lim.rlim_max != RLIM_INFINITY) {
      min = lim.rlim_max;
      max = lim.rlim_max;
    }
    do {
      lim.rlim_cur = min + (max - min) / 2;
      if (setrlimit(RLIMIT_NOFILE, &lim)) {
        max = lim.rlim_cur;
      } else {
        min = lim.rlim_cur;
      }
    } while (min + 1 < max);
  }
#endif  // __POSIX__
#ifdef _WIN32
  for (int fd = 0; fd <= 2; ++fd) {
    auto handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (handle == INVALID_HANDLE_VALUE ||
        GetFileType(handle) == FILE_TYPE_UNKNOWN) {
      // Ignore _close result. If it fails or not depends on used Windows
      // version. We will just check _open result.
      _close(fd);
      if (fd != _open("nul", _O_RDWR))
        ABORT();
    }
  }
#endif  // _WIN32
}

int ProcessGlobalArgs(std::vector<std::string>* args,
                      std::vector<std::string>* exec_args,
                      std::vector<std::string>* errors,
                      bool is_env) {
  // Parse a few arguments which are specific to Node.
  std::vector<std::string> v8_args;

  Mutex::ScopedLock lock(per_process::cli_options_mutex);
  options_parser::PerProcessOptionsParser::instance.Parse(
      args,
      exec_args,
      &v8_args,
      per_process::cli_options.get(),
      is_env ? kAllowedInEnvironment : kDisallowedInEnvironment,
      errors);

  if (!errors->empty()) return 9;

  std::string revert_error;
  for (const std::string& cve : per_process::cli_options->security_reverts) {
    Revert(cve.c_str(), &revert_error);
    if (!revert_error.empty()) {
      errors->emplace_back(std::move(revert_error));
      return 12;
    }
  }

  auto env_opts = per_process::cli_options->per_isolate->per_env;
  if (std::find(v8_args.begin(), v8_args.end(),
                "--abort-on-uncaught-exception") != v8_args.end() ||
      std::find(v8_args.begin(), v8_args.end(),
                "--abort_on_uncaught_exception") != v8_args.end()) {
    env_opts->abort_on_uncaught_exception = true;
  }

  // TODO(bnoordhuis) Intercept --prof arguments and start the CPU profiler
  // manually?  That would give us a little more control over its runtime
  // behavior but it could also interfere with the user's intentions in ways
  // we fail to anticipate.  Dillema.
  if (std::find(v8_args.begin(), v8_args.end(), "--prof") != v8_args.end()) {
    per_process::v8_is_profiling = true;
  }

#ifdef __POSIX__
  // Block SIGPROF signals when sleeping in epoll_wait/kevent/etc.  Avoids the
  // performance penalty of frequent EINTR wakeups when the profiler is running.
  // Only do this for v8.log profiling, as it breaks v8::CpuProfiler users.
  if (per_process::v8_is_profiling) {
    uv_loop_configure(uv_default_loop(), UV_LOOP_BLOCK_SIGNAL, SIGPROF);
  }
#endif

  std::vector<char*> v8_args_as_char_ptr(v8_args.size());
  if (v8_args.size() > 0) {
    for (size_t i = 0; i < v8_args.size(); ++i)
      v8_args_as_char_ptr[i] = &v8_args[i][0];
    int argc = v8_args.size();
    V8::SetFlagsFromCommandLine(&argc, &v8_args_as_char_ptr[0], true);
    v8_args_as_char_ptr.resize(argc);
  }

  // Anything that's still in v8_argv is not a V8 or a node option.
  for (size_t i = 1; i < v8_args_as_char_ptr.size(); i++)
    errors->push_back("bad option: " + std::string(v8_args_as_char_ptr[i]));

  if (v8_args_as_char_ptr.size() > 1) return 9;

  return 0;
}

int Init(std::vector<std::string>* argv,
         std::vector<std::string>* exec_argv,
         std::vector<std::string>* errors) {
  // Initialize prog_start_time to get relative uptime.
  per_process::prog_start_time = static_cast<double>(uv_now(uv_default_loop()));

  // Register built-in modules
  binding::RegisterBuiltinModules();

  if (!node_is_nwjs) {
  // Make inherited handles noninheritable.
  uv_disable_stdio_inheritance();
  } //node_is_nwjs

#ifdef NODE_REPORT
  // Cache the original command line to be
  // used in diagnostic reports.
  per_process::cli_options->cmdline = *argv;
#endif  //  NODE_REPORT

#if defined(NODE_V8_OPTIONS)
  // Should come before the call to V8::SetFlagsFromCommandLine()
  // so the user can disable a flag --foo at run-time by passing
  // --no_foo from the command line.
  V8::SetFlagsFromString(NODE_V8_OPTIONS, sizeof(NODE_V8_OPTIONS) - 1);
#endif

  std::shared_ptr<EnvironmentOptions> default_env_options =
      per_process::cli_options->per_isolate->per_env;
  {
    std::string text;
    default_env_options->pending_deprecation =
        credentials::SafeGetenv("NODE_PENDING_DEPRECATION", &text) &&
        text[0] == '1';
  }

  // Allow for environment set preserving symlinks.
  {
    std::string text;
    default_env_options->preserve_symlinks =
        credentials::SafeGetenv("NODE_PRESERVE_SYMLINKS", &text) &&
        text[0] == '1';
  }

  {
    std::string text;
    default_env_options->preserve_symlinks_main =
        credentials::SafeGetenv("NODE_PRESERVE_SYMLINKS_MAIN", &text) &&
        text[0] == '1';
  }

  if (default_env_options->redirect_warnings.empty()) {
    credentials::SafeGetenv("NODE_REDIRECT_WARNINGS",
                            &default_env_options->redirect_warnings);
  }

#if HAVE_OPENSSL
  std::string* openssl_config = &per_process::cli_options->openssl_config;
  if (openssl_config->empty()) {
    credentials::SafeGetenv("OPENSSL_CONF", openssl_config);
  }
#endif

#if !defined(NODE_WITHOUT_NODE_OPTIONS)
  std::string node_options;
  if (credentials::SafeGetenv("NODE_OPTIONS", &node_options)) {
    // [0] is expected to be the program name, fill it in from the real argv
    // and use 'x' as a placeholder while parsing.
    std::vector<std::string> env_argv = SplitString("x " + node_options, ' ');
    env_argv[0] = argv->at(0);

    const int exit_code = ProcessGlobalArgs(&env_argv, nullptr, errors, true);
    if (exit_code != 0) return exit_code;
  }
#endif

  const int exit_code = ProcessGlobalArgs(argv, exec_argv, errors, false);
  if (exit_code != 0) return exit_code;

  // Set the process.title immediately after processing argv if --title is set.
  if (!per_process::cli_options->title.empty())
    uv_set_process_title(per_process::cli_options->title.c_str());

#if 0 //defined(NODE_HAVE_I18N_SUPPORT)
  // If the parameter isn't given, use the env variable.
  if (per_process::cli_options->icu_data_dir.empty())
    credentials::SafeGetenv("NODE_ICU_DATA",
                            &per_process::cli_options->icu_data_dir);
  // Initialize ICU.
  // If icu_data_dir is empty here, it will load the 'minimal' data.
  if (!i18n::InitializeICUDirectory(per_process::cli_options->icu_data_dir)) {
    errors->push_back("could not initialize ICU "
                      "(check NODE_ICU_DATA or --icu-data-dir parameters)\n");
    return 9;
  }
  per_process::metadata.versions.InitializeIntlVersions();
#endif

  // We should set node_is_initialized here instead of in node::Start,
  // otherwise embedders using node::Init to initialize everything will not be
  // able to set it and native modules will not load for them.
  node_is_initialized = true;
  return 0;
}

// TODO(addaleax): Deprecate and eventually remove this.
void Init(int* argc,
          const char** argv,
          int* exec_argc,
          const char*** exec_argv) {
  std::vector<std::string> argv_(argv, argv + *argc);  // NOLINT
  std::vector<std::string> exec_argv_;
  std::vector<std::string> errors;

  // This (approximately) duplicates some logic that has been moved to
  // node::Start(), with the difference that here we explicitly call `exit()`.
  int exit_code = Init(&argv_, &exec_argv_, &errors);

  for (const std::string& error : errors)
    fprintf(stderr, "%s: %s\n", argv_.at(0).c_str(), error.c_str());
  if (exit_code != 0) exit(exit_code);

  if (per_process::cli_options->print_version) {
    printf("%s\n", NODE_VERSION);
    exit(0);
  }

  if (per_process::cli_options->print_v8_help) {
    V8::SetFlagsFromString("--help", 6);  // Doesn't return.
    UNREACHABLE();
  }

  *argc = argv_.size();
  *exec_argc = exec_argv_.size();
  // These leak memory, because, in the original code of this function, no
  // extra allocations were visible. This should be okay because this function
  // is only supposed to be called once per process, though.
  *exec_argv = Malloc<const char*>(*exec_argc);
  for (int i = 0; i < *exec_argc; ++i)
    (*exec_argv)[i] = strdup(exec_argv_[i].c_str());
  for (int i = 0; i < *argc; ++i)
    argv[i] = strdup(argv_[i].c_str());
}

void RunAtExit(Environment* env) {
  env->RunAtExitCallbacks();
}


uv_loop_t* GetCurrentEventLoop(Isolate* isolate) {
  HandleScope handle_scope(isolate);
  Local<Context> context = isolate->GetCurrentContext();
  if (context.IsEmpty())
    return nullptr;
  Environment* env = Environment::GetCurrent(context);
  if (env == nullptr)
    return nullptr;
  return env->event_loop();
}


void AtExit(void (*cb)(void* arg), void* arg) {
  //auto env = Environment::GetThreadLocalEnv();
  thread_ctx_st* tls_ctx = (struct thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (tls_ctx && tls_ctx->env) {
    AtExit(tls_ctx->env, cb, arg);
  }
}


void AtExit(Environment* env, void (*cb)(void* arg), void* arg) {
  CHECK_NOT_NULL(env);
  env->AtExit(cb, arg);
}


void RunBeforeExit(Environment* env) {
  env->RunBeforeExitCallbacks();

  if (!uv_loop_alive(env->event_loop()))
    EmitBeforeExit(env);
}


void EmitBeforeExit(Environment* env) {
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());
  Local<Value> exit_code = env->process_object()
                               ->Get(env->context(), env->exit_code_string())
                               .ToLocalChecked()
                               ->ToInteger(env->context())
                               .ToLocalChecked();
  ProcessEmit(env, "beforeExit", exit_code).ToLocalChecked();
}

int EmitExit(Environment* env) {
  // process.emit('exit')
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());
  Local<Object> process_object = env->process_object();
  process_object->Set(env->context(),
                      FIXED_ONE_BYTE_STRING(env->isolate(), "_exiting"),
                      True(env->isolate())).FromJust();

  Local<String> exit_code = env->exit_code_string();
  int code = process_object->Get(env->context(), exit_code).ToLocalChecked()
      ->Int32Value(env->context()).ToChecked();
  ProcessEmit(env, "exit", Integer::New(env->isolate(), code));

  // Reload exit code, it may be changed by `emit('exit')`
  return process_object->Get(env->context(), exit_code).ToLocalChecked()
      ->Int32Value(env->context()).ToChecked();
}


ArrayBufferAllocator* CreateArrayBufferAllocator() {
  return new ArrayBufferAllocator();
}


void FreeArrayBufferAllocator(ArrayBufferAllocator* allocator) {
  delete allocator;
}


IsolateData* CreateIsolateData(
    Isolate* isolate,
    uv_loop_t* loop,
    MultiIsolatePlatform* platform,
    ArrayBufferAllocator* allocator) {
  return new IsolateData(
        isolate,
        loop,
        platform,
        allocator != nullptr ? allocator->zero_fill_field() : nullptr);
}


void FreeIsolateData(IsolateData* isolate_data) {
  delete isolate_data;
}


Environment* CreateEnvironment(IsolateData* isolate_data,
                               Local<Context> context,
                               int argc,
                               const char* const* argv,
                               int exec_argc,
                               const char* const* exec_argv) {
  Isolate* isolate = context->GetIsolate();
  HandleScope handle_scope(isolate);
  Context::Scope context_scope(context);
  // TODO(addaleax): This is a much better place for parsing per-Environment
  // options than the global parse call.
  std::vector<std::string> args(argv, argv + argc);
  std::vector<std::string> exec_args(exec_argv, exec_argv + exec_argc);
  Environment* env = new Environment(isolate_data, context);
  env->Start(per_process::v8_is_profiling);
  env->CreateProcessObject(args, exec_args);
  return env;
}


void FreeEnvironment(Environment* env) {
  env->RunCleanup();
  delete env;
}


Environment* GetCurrentEnvironment(Local<Context> context) {
  return Environment::GetCurrent(context);
}


MultiIsolatePlatform* GetMainThreadMultiIsolatePlatform() {
  return v8_platform.Platform();
}


MultiIsolatePlatform* CreatePlatform(
    int thread_pool_size,
    node::tracing::TracingController* tracing_controller) {
  return new NodePlatform(thread_pool_size, tracing_controller);
}


MultiIsolatePlatform* InitializeV8Platform(int thread_pool_size) {
  v8_platform.Initialize(thread_pool_size);
  return v8_platform.Platform();
}


void FreePlatform(MultiIsolatePlatform* platform) {
  delete platform;
}

Local<Context> NewContext(Isolate* isolate,
                          Local<ObjectTemplate> object_template) {
  auto context = Context::New(isolate, nullptr, object_template);
  if (context.IsEmpty()) return context;
  HandleScope handle_scope(isolate);

  context->SetEmbedderData(
      ContextEmbedderIndex::kAllowWasmCodeGeneration, True(isolate));

  {
    // Run lib/internal/per_context.js
    Context::Scope context_scope(context);

    std::vector<Local<String>> parameters = {
        FIXED_ONE_BYTE_STRING(isolate, "global")};
    std::vector<Local<Value>> arguments = {context->Global()};
    MaybeLocal<Value> result = per_process::native_module_loader.CompileAndCall(
        context, "internal/per_context", &parameters, &arguments, nullptr);
    if (result.IsEmpty()) {
      // Execution failed during context creation.
      // TODO(joyeecheung): deprecate this signature and return a MaybeLocal.
      return Local<Context>();
    }
  }

  return context;
}


inline int Start(Isolate* isolate, IsolateData* isolate_data,
                 const std::vector<std::string>& args,
                 const std::vector<std::string>& exec_args) {
  HandleScope handle_scope(isolate);
  Local<Context> context = NewContext(isolate);
  Context::Scope context_scope(context);
  Environment env(isolate_data, context);
  env.Start(per_process::v8_is_profiling);
  env.CreateProcessObject(args, exec_args);

#if HAVE_INSPECTOR && NODE_USE_V8_PLATFORM
  CHECK(!env.inspector_agent()->IsListening());
  // Inspector agent can't fail to start, but if it was configured to listen
  // right away on the websocket port and fails to bind/etc, this will return
  // false.
  env.inspector_agent()->Start(args.size() > 1 ? args[1].c_str() : "",
                               env.options()->debug_options(),
                               env.inspector_host_port(),
                               true);
  if (env.options()->debug_options().inspector_enabled &&
      !env.inspector_agent()->IsListening()) {
    return 12;  // Signal internal error.
  }
#else
  // inspector_enabled can't be true if !HAVE_INSPECTOR or !NODE_USE_V8_PLATFORM
  // - the option parser should not allow that.
  CHECK(!env.options()->debug_options().inspector_enabled);
#endif  // HAVE_INSPECTOR && NODE_USE_V8_PLATFORM

  {
    Environment::AsyncCallbackScope callback_scope(&env);
    env.async_hooks()->push_async_ids(1, 0);
    LoadEnvironment(&env);
    env.async_hooks()->pop_async_id(1);
  }

  {
    SealHandleScope seal(isolate);
    bool more;
    env.performance_state()->Mark(
        node::performance::NODE_PERFORMANCE_MILESTONE_LOOP_START);
    do {
      uv_run(env.event_loop(), UV_RUN_DEFAULT);

      v8_platform.DrainVMTasks(isolate);

      more = uv_loop_alive(env.event_loop());
      if (more)
        continue;

      RunBeforeExit(&env);

      // Emit `beforeExit` if the loop became alive either after emitting
      // event, or after running some callbacks.
      more = uv_loop_alive(env.event_loop());
    } while (more == true);
    env.performance_state()->Mark(
        node::performance::NODE_PERFORMANCE_MILESTONE_LOOP_EXIT);
  }

  env.set_trace_sync_io(false);

  const int exit_code = EmitExit(&env);

  WaitForInspectorDisconnect(&env);

  env.set_can_call_into_js(false);
  env.stop_sub_worker_contexts();
  uv_tty_reset_mode();
  env.RunCleanup();
  RunAtExit(&env);

  v8_platform.DrainVMTasks(isolate);
  v8_platform.CancelVMTasks(isolate);
#if defined(LEAK_SANITIZER)
  __lsan_do_leak_check();
#endif

  return exit_code;
}

bool AllowWasmCodeGenerationCallback(
    Local<Context> context, Local<String>) {
  Local<Value> wasm_code_gen =
    context->GetEmbedderData(ContextEmbedderIndex::kAllowWasmCodeGeneration);
  return wasm_code_gen->IsUndefined() || wasm_code_gen->IsTrue();
}

Isolate* NewIsolate(ArrayBufferAllocator* allocator, uv_loop_t* event_loop) {
  Isolate::CreateParams params;
  if (!node_is_nwjs) {
  params.array_buffer_allocator = allocator;
  }
#ifdef NODE_ENABLE_VTUNE_PROFILING
  params.code_event_handler = vTune::GetVtuneCodeEventHandler();
#endif

  Isolate* isolate = Isolate::Allocate();
  if (isolate == nullptr)
    return nullptr;

  // Register the isolate on the platform before the isolate gets initialized,
  // so that the isolate can access the platform during initialization.
  v8_platform.Platform()->RegisterIsolate(isolate, event_loop);
  Isolate::Initialize(isolate, params);

  isolate->AddMessageListenerWithErrorLevel(OnMessage,
      Isolate::MessageErrorLevel::kMessageError |
      Isolate::MessageErrorLevel::kMessageWarning);
#if 0
  isolate->SetAbortOnUncaughtExceptionCallback(ShouldAbortOnUncaughtException);
  isolate->SetMicrotasksPolicy(MicrotasksPolicy::kExplicit);
#endif
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kScoped);
  isolate->SetFatalErrorHandler(OnFatalError);
  isolate->SetAllowWasmCodeGenerationCallback(AllowWasmCodeGenerationCallback);
  //v8::CpuProfiler::UseDetailedSourcePositionsForProfiling(isolate);

  return isolate;
}

inline int Start(uv_loop_t* event_loop,
                 const std::vector<std::string>& args,
                 const std::vector<std::string>& exec_args) {
  std::unique_ptr<ArrayBufferAllocator, decltype(&FreeArrayBufferAllocator)>
      allocator(CreateArrayBufferAllocator(), &FreeArrayBufferAllocator);
  Isolate* const isolate = NewIsolate(allocator.get(), event_loop);
  if (isolate == nullptr)
    return 12;  // Signal internal error.

  if (per_process::cli_options->print_version) {
    printf("%s\n", NODE_VERSION);
    return 0;
  }

  if (per_process::cli_options->print_v8_help) {
    V8::SetFlagsFromString("--help", 6);  // Doesn't return.
    UNREACHABLE();
  }

  {
    Mutex::ScopedLock scoped_lock(per_process::main_isolate_mutex);
    CHECK_NULL(per_process::main_isolate);
    per_process::main_isolate = isolate;
  }

  int exit_code;
  {
    Locker locker(isolate);
    Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope(isolate);
    std::unique_ptr<IsolateData, decltype(&FreeIsolateData)> isolate_data(
        CreateIsolateData(
            isolate,
            event_loop,
            v8_platform.Platform()),
        &FreeIsolateData);
    // TODO(addaleax): This should load a real per-Isolate option, currently
    // this is still effectively per-process.
    if (isolate_data->options()->track_heap_objects) {
      isolate->GetHeapProfiler()->StartTrackingHeapObjects(true);
    }
    exit_code =
        Start(isolate, isolate_data.get(), args, exec_args);
  }

  {
    Mutex::ScopedLock scoped_lock(per_process::main_isolate_mutex);
    CHECK_EQ(per_process::main_isolate, isolate);
    per_process::main_isolate = nullptr;
  }

  isolate->Dispose();
  v8_platform.Platform()->UnregisterIsolate(isolate);

  return exit_code;
}

#ifdef V8_USE_EXTERNAL_STARTUP_DATA
// Helper class to load the startup data files from disk.
//
// This is meant as a convenience for stand-alone binaries like d8, cctest,
// unittest. A V8 embedder would likely either handle startup data on their
// own or just disable the feature if they don't want to handle it at all,
// while tools like cctest need to work in either configuration. Hence this is
// not meant for inclusion in the general v8 library.
class StartupDataHandler {
 public:
  // Load startup data, and call the v8::V8::Set*DataBlob API functions.
  //
  // natives_blob and snapshot_blob will be loaded realitive to exec_path,
  // which would usually be the equivalent of argv[0].
  StartupDataHandler(const char* exec_path, const char* natives_blob,
                     const char* snapshot_blob);
  ~StartupDataHandler();

 private:
  static char* RelativePath(char** buffer, const char* exec_path,
                            const char* name);

  void LoadFromFiles(const char* natives_blob, const char* snapshot_blob);

  void Load(const char* blob_file, v8::StartupData* startup_data,
            void (*setter_fn)(v8::StartupData*));

  v8::StartupData natives_;
  v8::StartupData snapshot_;

  // Disallow copy & assign.
  StartupDataHandler(const StartupDataHandler& other);
  void operator=(const StartupDataHandler& other);
};

StartupDataHandler::StartupDataHandler(const char* exec_path,
                                       const char* natives_blob,
                                       const char* snapshot_blob) {
  // If we have (at least one) explicitly given blob, use those.
  // If not, use the default blob locations next to the d8 binary.
  if (natives_blob || snapshot_blob) {
    LoadFromFiles(natives_blob, snapshot_blob);
  } else {
    char* natives;
    char* snapshot;
    LoadFromFiles(RelativePath(&natives, exec_path, "natives_blob.bin"),
                  RelativePath(&snapshot, exec_path, "snapshot_blob.bin"));

    free(natives);
    free(snapshot);
  }
}


StartupDataHandler::~StartupDataHandler() {
  delete[] natives_.data;
  delete[] snapshot_.data;
}


char* StartupDataHandler::RelativePath(char** buffer, const char* exec_path,
                                       const char* name) {
  const char* last_slash = strrchr(exec_path, '/');
  if (last_slash) {
    int after_slash = last_slash - exec_path + 1;
    int name_length = static_cast<int>(strlen(name));
    *buffer = reinterpret_cast<char*>(calloc(after_slash + name_length + 1, 1));
    strncpy(*buffer, exec_path, after_slash);
    strncat(*buffer, name, name_length);
  } else {
    *buffer = strdup(name);
  }
  return *buffer;
}


void StartupDataHandler::LoadFromFiles(const char* natives_blob,
                                       const char* snapshot_blob) {
  Load(natives_blob, &natives_, v8::V8::SetNativesDataBlob);
  Load(snapshot_blob, &snapshot_, v8::V8::SetSnapshotDataBlob);
}


void StartupDataHandler::Load(const char* blob_file,
                              v8::StartupData* startup_data,
                              void (*setter_fn)(v8::StartupData*)) {
  startup_data->data = NULL;
  startup_data->raw_size = 0;

  if (!blob_file) return;

  FILE* file = fopen(blob_file, "rb");
  if (!file) return;

  fseek(file, 0, SEEK_END);
  startup_data->raw_size = ftell(file);
  rewind(file);

  startup_data->data = new char[startup_data->raw_size];
  int read_size = static_cast<int>(fread(const_cast<char*>(startup_data->data),
                                         1, startup_data->raw_size, file));
  fclose(file);

  if (startup_data->raw_size == read_size) (*setter_fn)(startup_data);
}

#endif  // V8_USE_EXTERNAL_STARTUP_DATA


int Start(int argc, char** argv) {
  atexit([] () { uv_tty_reset_mode(); });
  PlatformInit();
  //performance::performance_node_start = PERFORMANCE_NOW();

  CHECK_GT(argc, 0);

#ifdef NODE_ENABLE_LARGE_CODE_PAGES
  if (node::IsLargePagesEnabled()) {
    if (node::MapStaticCodeToLargePages() != 0) {
      fprintf(stderr, "Reverting to default page size\n");
    }
  }
#endif

  // Hack around with the argv pointer. Used for process.title = "blah".
  argv = uv_setup_args(argc, argv);

  std::vector<std::string> args(argv, argv + argc);
  std::vector<std::string> exec_args;
  std::vector<std::string> errors;
  // This needs to run *before* V8::Initialize().
  {
    const int exit_code = Init(&args, &exec_args, &errors);
    for (const std::string& error : errors)
      fprintf(stderr, "%s: %s\n", args.at(0).c_str(), error.c_str());
    if (exit_code != 0) return exit_code;
  }

#if HAVE_OPENSSL
  {
    std::string extra_ca_certs;
    if (credentials::SafeGetenv("NODE_EXTRA_CA_CERTS", &extra_ca_certs))
      crypto::UseExtraCaCerts(extra_ca_certs);
  }
#ifdef NODE_FIPS_MODE
  // In the case of FIPS builds we should make sure
  // the random source is properly initialized first.
  OPENSSL_init();
#endif  // NODE_FIPS_MODE
  // V8 on Windows doesn't have a good source of entropy. Seed it from
  // OpenSSL's pool.
  V8::SetEntropySource(crypto::EntropySource);
#endif  // HAVE_OPENSSL

#ifdef V8_USE_EXTERNAL_STARTUP_DATA
  //StartupDataHandler startup_data(argv[0], nullptr, nullptr);
#if defined(__APPLE__)
  V8::InitializeExternalStartupData(g_native_blob_path);
#else
  V8::InitializeExternalStartupData(argv[0]);
#endif
#endif
  V8::InitializeICUDefaultLocation(argv[0]);
  UErrorCode err = U_ZERO_ERROR;
  void* icu_data = V8::RawICUData();
  if (icu_data)
    udata_setCommonData((uint8_t*)icu_data, &err);

  InitializeV8Platform(per_process::cli_options->v8_thread_pool_size);
  V8::Initialize();
  //performance::performance_v8_start = PERFORMANCE_NOW();
  per_process::v8_initialized = true;
  const int exit_code =
      Start(uv_default_loop(), args, exec_args);
  per_process::v8_initialized = false;
  V8::Dispose();

  // uv_run cannot be called from the time before the beforeExit callback
  // runs until the program exits unless the event loop has any referenced
  // handles after beforeExit terminates. This prevents unrefed timers
  // that happen to terminate during shutdown from being run unsafely.
  // Since uv_run cannot be called, uv_async handles held by the platform
  // will never be fully cleaned up.
  v8_platform.Dispose();

  return exit_code;
}

NODE_EXTERN v8::Handle<v8::Value> CallNWTickCallback(Environment* env, const v8::Handle<v8::Value> ret) {
  return (*g_nw_tick_callback)(env, ret);
}

}  // namespace node

#if !HAVE_INSPECTOR
void Initialize() {}

NODE_MODULE_CONTEXT_AWARE_INTERNAL(inspector, Initialize)
#endif  // !HAVE_INSPECTOR

extern "C" {
void wakeup_callback(uv_async_t* handle) {
  // do nothing, just make libuv exit loop.
}

void idle_callback(uv_idle_t* handle) {
  // do nothing, just make libuv exit loop.
}

void timer_callback(uv_timer_t* timer) {
  // libuv would block unexpectedly with zero-timeout timer
  // this is a workaround of libuv bug #574:
  // https://github.com/joyent/libuv/issues/574
  uv_idle_start(static_cast<uv_idle_t*>(timer->data), idle_callback);
}

void close_async_cb(uv_handle_t* handle) {
  delete reinterpret_cast<uv_async_t*>(handle);
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (tls_ctx)
    tls_ctx->close_async_handle_done = 1;
}

void close_timer_cb(uv_handle_t* handle) {
  delete reinterpret_cast<uv_timer_t*>(handle);
}

void close_quit_timer_cb(uv_handle_t* handle) {
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (tls_ctx)
    tls_ctx->close_quit_timer_done = 1;
}

void close_idle_cb(uv_handle_t* handle) {
  delete reinterpret_cast<uv_idle_t*>(handle);
}

NODE_EXTERN int g_uv_run(void* loop, int mode) {
  return uv_run((uv_loop_t*)loop, (uv_run_mode)mode);
}

NODE_EXTERN void g_set_uv_run(UVRunFn uv_run_fn) {
  node::g_nw_uv_run = uv_run_fn;
}

NODE_EXTERN int g_node_start(int argc, char** argv) {
  return node::Start(argc, argv);
}

NODE_EXTERN void g_set_blob_path(const char* path) {
  node::g_native_blob_path = path;
}

NODE_EXTERN void g_msg_pump_nest_enter(msg_pump_context_t* ctx) {
  ctx->loop = uv_loop_new();

  ctx->wakeup_events->push_back((uv_async_t*)ctx->wakeup_event);
  ctx->wakeup_event = new uv_async_t;
  uv_async_init((uv_loop_t*)ctx->loop, (uv_async_t*)ctx->wakeup_event, wakeup_callback);
}

NODE_EXTERN void g_msg_pump_pre_loop(msg_pump_context_t* ctx) {
  ctx->idle_handle = new uv_idle_t;
  uv_idle_init((uv_loop_t*)ctx->loop, (uv_idle_t*)ctx->idle_handle);

  ctx->delay_timer = new uv_timer_t;
  ((uv_timer_t*)ctx->delay_timer)->data = ctx->idle_handle;
  uv_timer_init((uv_loop_t*)ctx->loop, (uv_timer_t*)ctx->delay_timer);
}

NODE_EXTERN void g_msg_pump_did_work(msg_pump_context_t* ctx) {
  if (!node::thread_ctx_created) return;
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (tls_ctx && tls_ctx->env) {
    v8::Isolate* isolate = tls_ctx->env->isolate();
    if (!isolate)
      return;
    v8::HandleScope handleScope(isolate);
    v8::Context::Scope cscope(tls_ctx->env->context());
    (*node::g_nw_uv_run)((uv_loop_t*)ctx->loop, UV_RUN_NOWAIT);
    node::CallNWTickCallback(tls_ctx->env, v8::Undefined(isolate));
  }
}

NODE_EXTERN void g_msg_pump_need_work(msg_pump_context_t* ctx) {
  node::thread_ctx_st* tls_ctx = nullptr;
  if (node::thread_ctx_created) {
    tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
    if (tls_ctx && tls_ctx->env) {
      tls_ctx->env->context()->Enter();
    }
  }
  (*node::g_nw_uv_run)((uv_loop_t*)ctx->loop, UV_RUN_ONCE);
  if (tls_ctx && tls_ctx->env) {
    tls_ctx->env->context()->Exit();
  }
}

NODE_EXTERN void g_msg_pump_delay_work(msg_pump_context_t* ctx, int sec) {
  node::thread_ctx_st* tls_ctx = nullptr;
  if (node::thread_ctx_created) {
    tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
    if (tls_ctx && tls_ctx->env) {
      tls_ctx->env->context()->Enter();
    }
  }
  uv_timer_start((uv_timer_t*)ctx->delay_timer, timer_callback, sec, 0);
  (*node::g_nw_uv_run)((uv_loop_t*)ctx->loop, UV_RUN_ONCE);
  uv_idle_stop((uv_idle_t*)ctx->idle_handle);
  uv_timer_stop((uv_timer_t*)ctx->delay_timer);
  if (tls_ctx && tls_ctx->env) {
    tls_ctx->env->context()->Exit();
  }
}

NODE_EXTERN void g_msg_pump_nest_leave(msg_pump_context_t* ctx) {
  uv_close((uv_handle_t*)(ctx->wakeup_event), close_async_cb);
  // Delete external loop.
  uv_loop_close((uv_loop_t*)ctx->loop);
  free((uv_loop_t*)ctx->loop);
  ctx->loop = nullptr;
    // // Restore previous async handle.
  ctx->wakeup_event = ctx->wakeup_events->back();
  ctx->wakeup_events->pop_back();
}

NODE_EXTERN uv_loop_t* g_uv_default_loop() {
  return uv_default_loop();
}

NODE_EXTERN void g_msg_pump_clean_ctx(msg_pump_context_t* ctx) {
  uv_close((uv_handle_t*)ctx->idle_handle, close_idle_cb);
  uv_run((uv_loop_t*)ctx->loop, UV_RUN_NOWAIT);
  ctx->idle_handle = nullptr;

  uv_close((uv_handle_t*)ctx->delay_timer, close_timer_cb);
  uv_run((uv_loop_t*)ctx->loop, UV_RUN_NOWAIT);
  ctx->delay_timer = nullptr;
}

NODE_EXTERN void g_msg_pump_sched_work(uv_async_t* wakeup_event) {
#ifdef _WIN32
  uv_async_send_nw(wakeup_event);
#else
  uv_async_send(wakeup_event);
#endif
}

NODE_EXTERN void g_msg_pump_ctor(uv_async_t** wakeup_event, int worker_support) {
  uv_init_nw(worker_support);
  node::g_worker_support = worker_support;
  *wakeup_event = new uv_async_t;
  uv_async_init(uv_default_loop(), *wakeup_event, wakeup_callback);
  node::g_nw_uv_run = (UVRunFn)uv_run;
}

NODE_EXTERN void g_msg_pump_dtor(uv_async_t** wakeup_event) {
  node::thread_ctx_st* tls_ctx = nullptr;
  tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  tls_ctx->close_async_handle_done = 0;
  uv_close(reinterpret_cast<uv_handle_t*>(*wakeup_event), close_async_cb);
  while (!tls_ctx->close_async_handle_done)
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
  uv_loop_close(uv_default_loop());
  *wakeup_event = nullptr;
  free(tls_ctx);
  uv_key_set(&node::thread_ctx_key, NULL);
}

NODE_EXTERN bool g_is_node_initialized() {
  return node::node_is_initialized;
}

NODE_EXTERN void g_call_tick_callback(node::Environment* env) {
  v8::HandleScope scope(env->isolate());
  v8::Context::Scope context_scope(env->context());
  node::Environment::AsyncCallbackScope callback_scope(env);

  env->KickNextTick();
}

// copied beginning of Start() until v8::Initialize()
NODE_EXTERN void g_setup_nwnode(int argc, char** argv, bool worker) {
  node::per_process::prog_start_time = static_cast<double>(uv_now(uv_default_loop()));
  node::node_is_initialized = true;
  node::node_is_nwjs = true;
  node::per_process::main_isolate = v8::Isolate::GetCurrent();
}

static void walk_cb(uv_handle_t* handle, void* arg) {
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)arg;
  if (uv_is_active(handle))
    tls_ctx->handle_counter++;  
}

static void quit_timer_cb(uv_timer_t* timer) {
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  assert(tls_ctx);
  tls_ctx->quit_flag = 1;
  //std::cerr << "quit timer timeout";
}

NODE_EXTERN void g_stop_nw_instance() {
  if (!node::g_worker_support)
    return;
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (!tls_ctx) //NWJS#6615
    return;
  bool more;
  uv_timer_t quit_timer;
  uv_loop_t* loop = tls_ctx->env->event_loop();
  uv_timer_init(loop, &quit_timer);
  uv_timer_start(&quit_timer, quit_timer_cb, 10000, 0);
  do {
    tls_ctx->handle_counter = 0;
    uv_walk(loop, walk_cb, tls_ctx);
    //std::cerr << "handles: " << tls_ctx->handle_counter;
    // quit timer and async hanle for loop wakeup
    if (tls_ctx->handle_counter <= 2)
      more = false;
    else
    //uv_print_active_handles(tls_ctx->env->event_loop(), stderr);
      more = uv_run(loop, UV_RUN_ONCE);
    if (more == false) {
      node::EmitBeforeExit(tls_ctx->env);

      // Emit `beforeExit` if the loop became alive either after emitting
      // event, or after running some callbacks.
      more = uv_loop_alive(loop);
      if (uv_run(loop, UV_RUN_NOWAIT) != 0)
        more = true;
      tls_ctx->handle_counter = 0;
      uv_walk(loop, walk_cb, tls_ctx);
      //std::cerr << "handles: " << tls_ctx->handle_counter;
      if (tls_ctx->handle_counter <= 2)
        more = false;
    }
  } while (more == true && !tls_ctx->quit_flag);
  uv_timer_stop(&quit_timer);
  tls_ctx->close_quit_timer_done = 0;
  uv_close(reinterpret_cast<uv_handle_t*>(&quit_timer), close_quit_timer_cb);
  while (!tls_ctx->close_quit_timer_done)
    uv_run(loop, UV_RUN_NOWAIT);
  struct node::node_module* mp, *mp2;
  for (mp = tls_ctx->modlist_builtin; mp != nullptr;) {
    mp2 = mp->nm_link;
    free(mp);
    mp = mp2;
  }
  for (mp = tls_ctx->modlist_linked; mp != nullptr;) {
    mp2 = mp->nm_link;
    free(mp);
    mp = mp2;
  }
  node::FreeEnvironment(tls_ctx->env);
  tls_ctx->env = nullptr;
  //std::cerr << "QUIT LOOP" << std::endl;
}

NODE_EXTERN void g_start_nw_instance(int argc, char *argv[], v8::Handle<v8::Context> context, void* icu_data) {

  UErrorCode err = U_ZERO_ERROR;
  if (icu_data)
    udata_setCommonData((uint8_t*)icu_data, &err);

  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope handle_scope(isolate);
  v8::Context::Scope context_scope(context);

  argv = uv_setup_args(argc, argv);

  if (!node::thread_ctx_created) {
    node::thread_ctx_created = 1;
    uv_key_create(&node::thread_ctx_key);
  }
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (!tls_ctx) {
    tls_ctx = (node::thread_ctx_st*)malloc(sizeof(node::thread_ctx_st));
    memset(tls_ctx, 0, sizeof(node::thread_ctx_st));
    uv_key_set(&node::thread_ctx_key, tls_ctx);
    node::binding::RegisterBuiltinModules();
  }
  node::IsolateData* isolate_data = node::CreateIsolateData(isolate, uv_default_loop());
  tls_ctx->env = node::CreateEnvironment(isolate_data, context, argc, argv, 0, nullptr);
  isolate->SetFatalErrorHandler(node::OnFatalError);
  isolate->AddMessageListener(node::OnMessage);
  //isolate->SetAutorunMicrotasks(false);
#if 0
  const char* path = argc > 1 ? argv[1] : nullptr;
  StartInspector(tls_ctx->env, path, node::debug_options);
#endif
  {
    node::Environment::AsyncCallbackScope callback_scope(tls_ctx->env);
    tls_ctx->env->async_hooks()->push_async_ids(1, 0);
    node::LoadEnvironment(tls_ctx->env);
    tls_ctx->env->async_hooks()->pop_async_id(1);
  }
}

NODE_EXTERN void g_set_nw_tick_callback(NWTickCallback tick_callback) {
  node::g_nw_tick_callback = tick_callback;
}

NODE_EXTERN void* g_get_node_env() {
  if (!node::thread_ctx_created)
    return nullptr;
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  return tls_ctx->env;
}

NODE_EXTERN void g_get_node_context(v8::Local<v8::Context>* ret) {
  *ret = v8::Local<v8::Context>::New(v8::Isolate::GetCurrent(), node::g_context);
}

NODE_EXTERN void g_set_node_context(v8::Isolate* isolate, v8::Local<v8::Context>* context) {
  node::g_context.Reset(isolate, *context);
}

NODE_EXTERN void* g_get_current_env(v8::Handle<v8::Context> context) {
  return node::Environment::GetCurrent(context);
}

NODE_EXTERN void g_emit_exit(node::Environment* env) {
  node::EmitExit(env);
}

NODE_EXTERN void g_run_at_exit(node::Environment* env) {
  node::RunAtExit(env);
}

NODE_EXTERN void g_promise_reject_callback(v8::PromiseRejectMessage* data) {
  node::task_queue::PromiseRejectCallback(*data);
}

NODE_EXTERN void g_uv_init_nw(int worker) {
  uv_init_nw(worker);
}

#ifdef __APPLE__

void UvNoOp(uv_async_t* handle) {
}

NODE_EXTERN bool g_nw_enter_dom() {
  if (!node::thread_ctx_created)
    return false;
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (tls_ctx && tls_ctx->env) {
    v8::Isolate* isolate = tls_ctx->env->isolate();
    v8::HandleScope handleScope(isolate);
    v8::Local<v8::Context> context = isolate->GetEnteredContext();
    if (context == tls_ctx->env->context()) {
      context->Exit();
      return true;
    }
  }
  return false;
}

NODE_EXTERN void g_nw_leave_dom(bool reenter) {
  if (!node::thread_ctx_created)
    return;
  node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
  if (reenter && tls_ctx && tls_ctx->env) {
    v8::Isolate* isolate = tls_ctx->env->isolate();
    v8::HandleScope handleScope(isolate);
    tls_ctx->env->context()->Enter();
  }
}

NODE_EXTERN void g_msg_pump_ctor_osx(msg_pump_context_t* ctx, void* EmbedThreadRunner, void* kevent_hook, void* data, int worker_support) {
  uv_init_nw(worker_support);
  node::g_worker_support = worker_support;
  // Add dummy handle for libuv, otherwise libuv would quit when there is
  // nothing to do.
  ctx->dummy_uv_handle = new uv_async_t;
  uv_async_init(uv_default_loop(), (uv_async_t*)ctx->dummy_uv_handle, UvNoOp);

  // Start worker that will interrupt main loop when having uv events.
  ctx->embed_sem = new uv_sem_t;
  uv_sem_init((uv_sem_t*)ctx->embed_sem, 0);
  ctx->embed_thread = new uv_thread_t;
  uv_thread_create((uv_thread_t*)ctx->embed_thread, (uv_thread_cb)EmbedThreadRunner, data);

  uv_loop_t* uvloop = uv_default_loop();
  uvloop->keventfunc = kevent_hook;

  ctx->loop = uvloop;

  // Execute loop for once.
  uv_run(uv_default_loop(), UV_RUN_NOWAIT);
  node::g_nw_uv_run = (UVRunFn)uv_run;
}

NODE_EXTERN void g_msg_pump_dtor_osx(msg_pump_context_t* ctx) {
  uv_thread_join((uv_thread_t*)ctx->embed_thread);

  delete (uv_async_t*)ctx->dummy_uv_handle;
  ctx->dummy_uv_handle = nullptr;

  delete (uv_sem_t*)ctx->embed_sem;
  ctx->embed_sem = nullptr;

  delete (uv_thread_t*)ctx->embed_thread;
  ctx->embed_thread = nullptr;
}

NODE_EXTERN int g_nw_uvrun_nowait() {
  return (*node::g_nw_uv_run)(uv_default_loop(), UV_RUN_NOWAIT);
}

NODE_EXTERN int g_uv_runloop_once() {
  if (node::thread_ctx_created) {
    node::thread_ctx_st* tls_ctx = (node::thread_ctx_st*)uv_key_get(&node::thread_ctx_key);
    if (tls_ctx && tls_ctx->env) {
      v8::Isolate* isolate = tls_ctx->env->isolate();
      v8::HandleScope handleScope(isolate);
      v8::Context::Scope cscope(tls_ctx->env->context());
      return (*node::g_nw_uv_run)(uv_default_loop(), UV_RUN_ONCE);
    }
  }
  return (*node::g_nw_uv_run)(uv_default_loop(), UV_RUN_ONCE);
}

NODE_EXTERN int g_uv_backend_timeout() {
  return  uv_backend_timeout(uv_default_loop());
}

NODE_EXTERN void g_uv_sem_post(msg_pump_context_t* ctx) {
  uv_sem_post((uv_sem_t*)ctx->embed_sem);
}

NODE_EXTERN int g_uv_backend_fd() {
  return uv_backend_fd(uv_default_loop());
}

NODE_EXTERN void g_uv_sem_wait(msg_pump_context_t* ctx) {
  uv_sem_wait((uv_sem_t*)ctx->embed_sem);
}
#endif
}
