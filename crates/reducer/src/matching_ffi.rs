#[cxx::bridge(namespace = "reducer_matching")]
mod ffi {
    // Plain descriptor for contiguous element-queue storage
    #[derive(Debug)]
    pub struct EqView {
        pub data: *mut u8, // base pointer to contiguous storage (shared)
        pub n_elems: u32,  // ring size (power of two)
        pub buf_len: u32,  // data buffer size (power of two)
    }

    extern "Rust" {
        type MatchingCore;

        /// Create a new MatchingCore from ingest->matching element-queue
        /// descriptors.
        fn matching_core_new(queues: &CxxVector<EqView>, shard: u32) -> Box<MatchingCore>;
        /// Run the core loop until stopped.
        fn matching_core_run(self: Pin<&mut MatchingCore>);
        /// Request cooperative stop.
        fn matching_core_stop(self: Pin<&mut MatchingCore>);
    }
}

use crate::matching_core::MatchingCore;

impl MatchingCore {
    fn from_views(views: &cxx::CxxVector<ffi::EqView>, shard: u32) -> Self {
        let mut v = Vec::with_capacity(views.len());
        for ev in views {
            v.push((ev.data as usize, ev.n_elems, ev.buf_len));
        }
        MatchingCore::new(&v[..], shard)
    }
}

fn matching_core_new(queues: &cxx::CxxVector<ffi::EqView>, shard: u32) -> Box<MatchingCore> {
    Box::new(MatchingCore::from_views(queues, shard))
}

impl MatchingCore {
    fn matching_core_run(self: core::pin::Pin<&mut Self>) {
        // Safe because we don't move after pin
        let core_ref: &mut MatchingCore = unsafe { self.get_unchecked_mut() };
        core_ref.run();
    }

    fn matching_core_stop(self: core::pin::Pin<&mut Self>) {
        let core_ref: &mut MatchingCore = unsafe { self.get_unchecked_mut() };
        core_ref.stop();
    }
}
