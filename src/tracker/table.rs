//! Track bookkeeping for the continuity methods.

use std::collections::HashMap;

use crate::model::{Cid, Endpoint, FlowKey, HeaderForm, Observation};

use super::TrackId;

pub(super) struct Track {
    pub id: TrackId,
    /// The 4-tuple the track was last filed under.
    pub flow: FlowKey,
    /// Capture time of the track's first observation.
    pub started_us: u64,
    pub last_seen_us: u64,
    /// The track's first observation was a long-header packet.
    pub opened_by_handshake: bool,
    /// The track that held this one's tuple before it, if any.
    pub displaced: Option<TrackId>,
}

#[derive(Default)]
pub(super) struct Table {
    tracks: Vec<Track>,
    by_flow: HashMap<FlowKey, TrackId>,
    by_cid: HashMap<(Endpoint, Cid), TrackId>,
    by_server: HashMap<Endpoint, Vec<TrackId>>,
}

impl Table {
    pub fn get(&self, id: TrackId) -> &Track {
        &self.tracks[id.0 as usize]
    }

    /// The track currently holding this observation's 4-tuple.
    pub fn on_flow(&self, obs: &Observation) -> Option<&Track> {
        self.by_flow.get(&obs.flow()).map(|id| self.get(*id))
    }

    /// The track that first exposed any connection ID on this observation,
    /// toward the same server.
    pub fn by_cid(&self, obs: &Observation) -> Option<TrackId> {
        obs.cids()
            .find_map(|cid| self.by_cid.get(&(obs.server(), cid)).copied())
    }

    /// Every track opened toward `server`, oldest first.
    pub fn toward(&self, server: Endpoint) -> &[TrackId] {
        self.by_server.get(&server).map_or(&[], Vec::as_slice)
    }

    fn register_cids(&mut self, id: TrackId, obs: &Observation) {
        for cid in obs.cids() {
            self.by_cid.entry((obs.server(), cid)).or_insert(id);
        }
    }

    /// Open a new track for `obs`. With `claim_flow`, the track takes over
    /// the observation's 4-tuple from whatever held it.
    pub fn open(&mut self, obs: &Observation, claim_flow: bool) -> TrackId {
        let id = TrackId(self.tracks.len() as u32);
        let flow = obs.flow();
        let displaced = if claim_flow {
            self.by_flow.insert(flow, id)
        } else {
            None
        };
        self.tracks.push(Track {
            id,
            flow,
            started_us: obs.timestamp_us,
            last_seen_us: obs.timestamp_us,
            opened_by_handshake: obs.transport.header == HeaderForm::Long,
            displaced,
        });
        self.by_server.entry(obs.server()).or_default().push(id);
        self.register_cids(id, obs);
        id
    }

    /// File `obs` under an existing track. The track follows the
    /// observation to its 4-tuple unless another track holds that tuple.
    pub fn file(&mut self, id: TrackId, obs: &Observation) {
        let flow = obs.flow();
        let holder = *self.by_flow.entry(flow).or_insert(id);
        let track = &mut self.tracks[id.0 as usize];
        if holder == id {
            track.flow = flow;
        }
        track.last_seen_us = track.last_seen_us.max(obs.timestamp_us);
        self.register_cids(id, obs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{c2s, s2c, ObsExt, SEC};

    #[test]
    fn open_claims_the_flow_and_remembers_what_it_displaced() {
        let mut table = Table::default();
        let first = table.open(&c2s(0, 1, 5000), true);
        assert_eq!(table.on_flow(&s2c(1, 1, 5000)).unwrap().id, first);
        assert_eq!(table.get(first).displaced, None);
        assert!(!table.get(first).opened_by_handshake);

        let second = table.open(&c2s(SEC, 1, 5000).initial(9), true);
        assert_eq!(table.on_flow(&c2s(SEC, 1, 5000)).unwrap().id, second);
        assert_eq!(table.get(second).displaced, Some(first));
        assert_eq!(table.get(second).started_us, SEC);
        assert!(table.get(second).opened_by_handshake);
    }

    #[test]
    fn open_without_claiming_leaves_the_flow_alone() {
        let mut table = Table::default();
        let holder = table.open(&c2s(SEC, 1, 5000), true);
        let side = table.open(&c2s(0, 1, 5000), false);
        assert_ne!(holder, side);
        assert_eq!(table.on_flow(&c2s(SEC, 1, 5000)).unwrap().id, holder);
        assert_eq!(table.get(side).displaced, None);
    }

    #[test]
    fn filing_follows_a_track_to_a_free_tuple_only() {
        let mut table = Table::default();
        let a = table.open(&c2s(0, 1, 5000).dcid(7), true);
        let b = table.open(&c2s(0, 2, 5000), true);

        table.file(a, &c2s(SEC, 1, 6000).dcid(7));
        assert_eq!(table.on_flow(&c2s(SEC, 1, 6000)).unwrap().id, a);
        assert_eq!(table.get(a).flow.client.port, 6000);
        assert_eq!(table.get(a).last_seen_us, SEC);

        table.file(a, &c2s(2 * SEC, 2, 5000).dcid(7));
        assert_eq!(table.on_flow(&c2s(2 * SEC, 2, 5000)).unwrap().id, b);
        assert_eq!(table.get(a).flow.client.port, 6000);
    }

    #[test]
    fn filing_a_late_record_does_not_move_last_seen_backwards() {
        let mut table = Table::default();
        let a = table.open(&c2s(5 * SEC, 1, 5000), true);
        table.file(a, &c2s(SEC, 1, 5000));
        assert_eq!(table.get(a).last_seen_us, 5 * SEC);
    }

    #[test]
    fn a_connection_id_belongs_to_the_track_that_showed_it_first() {
        let mut table = Table::default();
        let a = table.open(&c2s(0, 1, 5000).dcid(7), true);
        let b = table.open(&c2s(0, 2, 5000), true);
        table.file(b, &c2s(1, 2, 5000).dcid(7));

        assert_eq!(table.by_cid(&c2s(2, 3, 5000).dcid(7)), Some(a));
        assert_eq!(table.by_cid(&c2s(2, 3, 5000).dcid(8)), None);
        assert_eq!(table.by_cid(&c2s(2, 3, 5000)), None);

        let elsewhere = Endpoint {
            addr: crate::model::Addr::new(192, 0, 2, 99),
            port: 443,
        };
        assert_eq!(table.by_cid(&c2s(2, 3, 5000).dcid(7).to(elsewhere)), None);
        assert_eq!(table.toward(crate::testkit::server()), [a, b]);
        assert!(table.toward(elsewhere).is_empty());
    }
}
