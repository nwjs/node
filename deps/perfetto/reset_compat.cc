// nwjs: compat shim for the Chromium-linked perfetto.
//
// NW links the Chromium-built perfetto (Windows: ../nw/obj/third_party/
// perfetto/libperfettonode.lib; macOS: -force_load libperfettonode.a) so that
// node and the co-linked Chromium v8 share one perfetto instance. That library
// is built from Chromium's perfetto, where Message::Reset gained a third
// `Encoding` parameter and the two-argument overload became an inline
// forwarder, so it exports no out-of-line two-argument Message::Reset. This
// SDK's headers (58.2, pre-Encoding) declare the two-argument Reset
// out-of-line (sdk/perfetto.cc:14566) and its inline machinery (e.g.
// IncrementalState::Clear -> serialized_interned_data.Reset()) needs exactly
// that symbol. Define it here, mirroring the 58.2 implementation. The member
// layout is a prefix-compatible subset of Chromium's (its extra `encoding_`
// field is declared last), so this is sound for the objects node's SDK-driven
// code creates.
//
// Everything else node's inlined SDK code calls resolves against
// libperfettonode; only this definition is provided here, and it cannot
// collide (Chromium's library does not define this symbol out-of-line).

#define PERFETTO_IMPLEMENTATION 1
#include "perfetto.h"

namespace protozero {

void Message::Reset(ScatteredStreamWriter* stream_writer, MessageArena* arena) {
  static_assert(std::is_trivially_constructible<Message>::value,
                "Message must be trivially constructible");
  static_assert(std::is_trivially_destructible<Message>::value,
                "Message must be trivially destructible");
  stream_writer_ = stream_writer;
  arena_ = arena;
  size_ = 0;
  size_field_ = nullptr;
  nested_message_ = nullptr;
  message_state_ = MessageState::kNotFinalized;
}

}  // namespace protozero
