// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <reducer/test/core_shim.h>

#include <reducer/disabled_metrics.h>
#include <reducer/logging/logging_core.h>
#include <reducer/matching/matching_core.h>
#include <reducer/null_publisher.h>
#include <reducer/rpc_queue_matrix.h>

#include <util/element_queue_cpp.h>
#include <util/element_queue_writer.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using WriterRef = std::reference_wrapper<ElementQueueWriter>;

// Test queues only ever hold a handful of messages, so they are sized far
// below the production defaults (8 MiB per queue) to keep a core instance
// cheap enough to build per test case.
constexpr u32 kQueueElems = 1u << 12;
constexpr u32 kQueueBufLen = 1u << 20;

// Upper bound on handling passes in one pump(), so a core that always reports
// progress cannot hang the test binary.
constexpr int64_t kMaxPumpPasses = 4096;

// Idle passes pump() must see in a row before it calls the core quiescent.
//
// One is not enough. A core's virtual clock starts with no current timeslot, so
// the pass that reads the first message updates that message's input, finds
// VirtualClock::is_current() false (there is no current timeslot yet), leaves
// the message unread and reports no progress; only VirtualClock::advance() at
// the end of that pass seeds the timeslot. The message is handled on the pass
// after. Stopping at the first idle pass would therefore report a fresh core as
// having consumed nothing, which is what it looks like from the outside
// (`reducer/util/virtual_clock.cc`).
constexpr int kIdlePassesUntilQuiescent = 2;

// Writes a lifecycle marker to stderr when OTN_SHIM_TRACE=1.
//
// A core is a C++ object created and dropped by a Rust test binary. When one of
// them dies the way glibc reports heap damage -- a bare "corrupted double-linked
// list" and SIGABRT, raised at the next allocation rather than at the offending
// write -- the output says nothing about which core, or whether it died being
// built or being torn down. These markers bound each phase so the last one
// printed names the phase that failed.
void trace(char const *phase, std::string_view core)
{
  static bool const enabled = []() {
    char const *value = std::getenv("OTN_SHIM_TRACE");
    return value != nullptr && value[0] == '1';
  }();

  if (!enabled) {
    return;
  }

  std::fprintf(stderr, "[core_shim] %s %.*s\n", phase, static_cast<int>(core.size()), core.data());
  std::fflush(stderr);
}

// A core instance plus the edges around it, with the parts of Core that tests
// need to drive exposed.
class ShimCore {
public:
  virtual ~ShimCore() = default;

  // Runs one Core::handle_rpc() pass. Returns whether any message was handled.
  virtual bool step() = 0;

  // Marks every upstream edge as having reached `timestamp`.
  // Returns 0, or the negative errno the virtual clock rejected it with.
  virtual int advance_inputs(u64 timestamp) = 0;

  // Writer for an upstream edge, or nullptr if this core has no such edge.
  virtual ElementQueueWriter *in_edge(std::string_view name) = 0;

  // Reader for a downstream edge, or nullptr if this core has no such edge.
  virtual ElementQueue *out_edge(std::string_view name) = 0;
};

// Grants the shim access to the stepping seam a core inherits from Core:
// handle_rpc() and the virtual clock, both protected.
//
// Stepping the core directly is what makes tests deterministic -- production
// reaches handle_rpc() from a libuv timer on the core's own thread.
template <typename CoreT> class SteppableCore : public CoreT {
public:
  using CoreT::CoreT;

  bool step() { return this->handle_rpc(); }

  int advance_inputs(u64 timestamp)
  {
    auto &clock = this->virtual_clock_;

    for (size_t i = 0; i < clock.n_inputs(); ++i) {
      if (!clock.can_update(i)) {
        // Input is already ahead of the clock's timeslot; it will be picked up
        // when the clock advances.
        continue;
      }
      if (int res = clock.update(i, timestamp); res < 0) {
        return res;
      }
    }

    return 0;
  }
};

class MatchingShim final : public ShimCore {
public:
  explicit MatchingShim(u64 initial_timestamp)
      : ingest_to_matching_(1, 1, kQueueElems, kQueueBufLen),
        matching_to_aggregation_(1, 1, kQueueElems, kQueueBufLen),
        matching_to_logging_(1, 1, kQueueElems, kQueueBufLen),
        core_(
            ingest_to_matching_,
            matching_to_aggregation_,
            matching_to_logging_,
            /* geoip_path */ std::nullopt,
            /* shard_num */ 0,
            initial_timestamp),
        ingest_writers_(ingest_to_matching_.make_writers<WriterRef>(0)),
        aggregation_readers_(matching_to_aggregation_.make_readers(0)),
        logging_readers_(matching_to_logging_.make_readers(0))
  {
    // Matching receives only from in-process cores, so the reducer flags its
    // connection as authenticated instead of running the auth handshake.
    core_.set_connection_authenticated();
  }

  bool step() override { return core_.step(); }
  int advance_inputs(u64 timestamp) override { return core_.advance_inputs(timestamp); }

  ElementQueueWriter *in_edge(std::string_view name) override
  {
    if (name == "ingest") {
      return &ingest_writers_[0].get();
    }
    return nullptr;
  }

  ElementQueue *out_edge(std::string_view name) override
  {
    if (name == "aggregation") {
      return &aggregation_readers_[0];
    }
    if (name == "logging") {
      return &logging_readers_[0];
    }
    return nullptr;
  }

private:
  reducer::RpcQueueMatrix ingest_to_matching_;
  reducer::RpcQueueMatrix matching_to_aggregation_;
  reducer::RpcQueueMatrix matching_to_logging_;

  SteppableCore<reducer::matching::MatchingCore> core_;

  std::vector<WriterRef> ingest_writers_;
  std::vector<ElementQueue> aggregation_readers_;
  std::vector<ElementQueue> logging_readers_;
};

class LoggingShim final : public ShimCore {
public:
  explicit LoggingShim(u64 initial_timestamp)
      : ingest_to_logging_(1, 1, kQueueElems, kQueueBufLen),
        matching_to_logging_(1, 1, kQueueElems, kQueueBufLen),
        aggregation_to_logging_(1, 1, kQueueElems, kQueueBufLen),
        core_(
            ingest_to_logging_,
            matching_to_logging_,
            aggregation_to_logging_,
            publisher_.make_writer(0),
            disabled_metrics_,
            /* shard_num */ 0,
            initial_timestamp),
        ingest_writers_(ingest_to_logging_.make_writers<WriterRef>(0)),
        matching_writers_(matching_to_logging_.make_writers<WriterRef>(0)),
        aggregation_writers_(aggregation_to_logging_.make_writers<WriterRef>(0))
  {
    core_.set_connection_authenticated();
  }

  bool step() override { return core_.step(); }
  int advance_inputs(u64 timestamp) override { return core_.advance_inputs(timestamp); }

  ElementQueueWriter *in_edge(std::string_view name) override
  {
    if (name == "ingest") {
      return &ingest_writers_[0].get();
    }
    if (name == "matching") {
      return &matching_writers_[0].get();
    }
    if (name == "aggregation") {
      return &aggregation_writers_[0].get();
    }
    return nullptr;
  }

  // Logging is a sink: it publishes to a TSDB writer, not to another core.
  ElementQueue *out_edge(std::string_view) override { return nullptr; }

private:
  reducer::RpcQueueMatrix ingest_to_logging_;
  reducer::RpcQueueMatrix matching_to_logging_;
  reducer::RpcQueueMatrix aggregation_to_logging_;

  // Internal metrics go nowhere in tests; both of these outlive the core,
  // which holds a reference to the disabled-metrics set.
  reducer::NullPublisher publisher_;
  reducer::DisabledMetrics disabled_metrics_{"", ""};

  SteppableCore<reducer::logging::LoggingCore> core_;

  std::vector<WriterRef> ingest_writers_;
  std::vector<WriterRef> matching_writers_;
  std::vector<WriterRef> aggregation_writers_;
};

std::unique_ptr<ShimCore> make_core(std::string_view name, u64 initial_timestamp)
{
  trace("constructing", name);

  std::unique_ptr<ShimCore> instance;
  if (name == "matching") {
    instance = std::make_unique<MatchingShim>(initial_timestamp);
  } else if (name == "logging") {
    instance = std::make_unique<LoggingShim>(initial_timestamp);
  } else {
    return nullptr;
  }

  trace("constructed", name);

  return instance;
}

} // namespace

// Handle handed back to Rust. Holds the core and the message of the last
// failure, so a negative return code can be explained.
struct otn_core_shim {
  std::unique_ptr<ShimCore> core;
  std::string kind;
  std::string last_error;

  otn_core_shim(std::unique_ptr<ShimCore> c, std::string_view k) : core(std::move(c)), kind(k) {}
};

namespace {

// Steps the core until it reports no progress `kIdlePassesUntilQuiescent` times
// in a row. Returns the number of passes that handled at least one message.
int64_t pump_to_quiescence(ShimCore &core)
{
  int64_t handled = 0;
  int idle = 0;

  for (int64_t pass = 0; pass < kMaxPumpPasses && idle < kIdlePassesUntilQuiescent; ++pass) {
    if (core.step()) {
      ++handled;
      idle = 0;
    } else {
      ++idle;
    }
  }

  return handled;
}

// Runs `fn`, turning an escaped C++ exception into an error code plus a message
// on the handle: exceptions must not cross the C ABI, and the reason a core
// rejected input (out-of-order timestamps, for instance) is the interesting
// part of the failure.
template <typename Fn> int64_t guarded(otn_core_shim *shim, Fn &&fn)
{
  if (shim == nullptr) {
    return OTN_SHIM_ERR_INVALID;
  }

  shim->last_error.clear();

  try {
    return fn();
  } catch (std::exception const &e) {
    shim->last_error = e.what();
    return OTN_SHIM_ERR_EXCEPTION;
  } catch (...) {
    shim->last_error = "unknown exception";
    return OTN_SHIM_ERR_EXCEPTION;
  }
}

} // namespace

extern "C" {

otn_core_shim *otn_core_shim_create(char const *core, uint64_t initial_timestamp)
{
  if (core == nullptr) {
    return nullptr;
  }

  try {
    auto instance = make_core(core, initial_timestamp);
    if (instance == nullptr) {
      return nullptr;
    }
    return new otn_core_shim(std::move(instance), core);
  } catch (...) {
    // No handle exists yet to carry the message; the null return is all the
    // caller can act on.
    return nullptr;
  }
}

void otn_core_shim_destroy(otn_core_shim *shim)
{
  if (shim == nullptr) {
    return;
  }

  std::string const kind = shim->kind;
  trace("destroying", kind);

  delete shim;

  trace("destroyed", kind);
}

int64_t otn_core_shim_inject(otn_core_shim *shim, char const *edge, uint8_t const *data, size_t len)
{
  return guarded(shim, [&]() -> int64_t {
    if (edge == nullptr || data == nullptr || len == 0) {
      return OTN_SHIM_ERR_INVALID;
    }

    auto *writer = shim->core->in_edge(edge);
    if (writer == nullptr) {
      shim->last_error = std::string("no upstream edge named '") + edge + "'";
      return OTN_SHIM_ERR_INVALID;
    }

    auto buf = writer->start_write(static_cast<u32>(len));
    if (!buf) {
      shim->last_error = "element queue write failed: " + buf.error().message();
      return OTN_SHIM_ERR_INVALID;
    }

    std::memcpy(buf.value(), data, len);
    writer->finish_write();

    return OTN_SHIM_OK;
  });
}

int64_t otn_core_shim_pump(otn_core_shim *shim)
{
  return guarded(shim, [&]() -> int64_t { return pump_to_quiescence(*shim->core); });
}

int64_t otn_core_shim_advance_clock(otn_core_shim *shim, uint64_t timestamp)
{
  return guarded(shim, [&]() -> int64_t {
    if (int res = shim->core->advance_inputs(timestamp); res < 0) {
      shim->last_error = "virtual clock rejected timestamp " + std::to_string(timestamp) + ": " + std::to_string(res);
      return OTN_SHIM_ERR_INVALID;
    }

    // Same quiescence rule as pump(): the pass that completes the timeslot may
    // be preceded by one that only seeds the clock.
    pump_to_quiescence(*shim->core);

    return OTN_SHIM_OK;
  });
}

int64_t otn_core_shim_drain(otn_core_shim *shim, char const *edge, uint8_t *out, size_t cap)
{
  return guarded(shim, [&]() -> int64_t {
    if (edge == nullptr || out == nullptr) {
      return OTN_SHIM_ERR_INVALID;
    }

    auto *queue = shim->core->out_edge(edge);
    if (queue == nullptr) {
      shim->last_error = std::string("no downstream edge named '") + edge + "'";
      return OTN_SHIM_ERR_INVALID;
    }

    queue->start_read_batch();

    int const peeked = queue->peek();
    if (peeked <= 0) {
      queue->finish_read_batch();
      return OTN_SHIM_ERR_EMPTY;
    }
    if (static_cast<size_t>(peeked) > cap) {
      // Leave the message queued so the caller can retry with a bigger buffer.
      queue->finish_read_batch();
      shim->last_error =
          "buffer of " + std::to_string(cap) + " bytes too small for a " + std::to_string(peeked) + " byte message";
      return OTN_SHIM_ERR_NOSPACE;
    }

    char *msg{nullptr};
    int const len = queue->read(msg);
    if (len < 0) {
      queue->finish_read_batch();
      shim->last_error = "element queue read failed: " + std::to_string(len);
      return OTN_SHIM_ERR_INVALID;
    }

    std::memcpy(out, msg, static_cast<size_t>(len));
    queue->finish_read_batch();

    return len;
  });
}

char const *otn_core_shim_last_error(otn_core_shim const *shim)
{
  if (shim == nullptr) {
    return "";
  }
  return shim->last_error.c_str();
}

} // extern "C"
