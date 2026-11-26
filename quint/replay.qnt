// -*- mode: Bluespec; -*-
// The Q1 instance the Connect replay drives, at the constants quint/check.py
// states, with two history flags that the fixture recipes read and one
// recipe step that reaches a reopen.
//
// `restarted` holds once client c1 has restarted its handshake while the
// owner's pending handshake for it named another client nonce, that is,
// after a stale HELLO displaced it. `repeated` holds when client c1's
// CONFIRM repeat count was positive in the state before the last action.
// Each fixture is the counterexample of one inverted invariant below,
// recorded by `quint run --mbt` under a pinned seed (see
// crates/kestrike/src/net/q1_replay_tests.rs).
module replay {
  import session(CLIENTS = Set("c1", "c2"), BOOTS = 2, REKEYS = 1, FAULTS = 2, CAP_TO_OWNER = 2, CAP_TO_CLIENT = 1,
                 COPIES = 2, REPEATS = 2) as Q from "./session"

  var restarted: bool
  var repeated: bool

  action history = all {
    restarted' = (restarted or (Q::last.restart and Q::last.pendingForeign and Q::last.peer == "c1")),
    repeated' = Q::s.clients.get("c1").repeats > 0,
  }

  action init = all { Q::init, restarted' = false, repeated' = false }

  action step = all { Q::step, history }

  // The step the repeat-then-rekey recipe runs: client c1's retries and
  // bootstrap deliveries and the re-key, each a choice of `step`, so its
  // traces are traces of `step`.
  action bootstrapThenRekey = all {
    any {
      nondet peer = Set("c1").oneOf()
      nondet data = Set(false).oneOf()
      any { Q::retry(peer), Q::deliverToOwner(peer, data), Q::deliverToClient(peer, data) },
      Q::rekey,
    },
    history,
  }

  // The step the reopen recipe runs: client c1's retries once its exchange is
  // idle, its deliveries and data frames and its reopen beside the active
  // session, each a choice of `step`, so its traces are traces of `step`.
  // Early retries and stability stay out: each early retry spends a fault
  // the reopen needs, and a reopen happens only before stability. `step`'s
  // random traces spend every fault or stabilize before a client activates,
  // so they reach no reopen.
  action openThenReopen = all {
    nondet peer = Set("c1").oneOf()
    nondet data = Set(false, true).oneOf()
    any {
      all { not(Q::awaiting(Q::s, peer)), Q::retry(peer) },
      Q::deliverToOwner(peer, data), Q::deliverToClient(peer, data), Q::reopen(peer),
      Q::ownerData(peer), Q::clientData(peer),
    },
    history,
  }

  // The pending-displacement fixture: client c1 activates after a client
  // restarted while a stale HELLO held the owner's pending handshake for it;
  // the recorded trace shows c1 restarting.
  val noDisplacedActivation = not(restarted and Q::isActive(Q::s, "c1"))

  // The clean-activation fixture: client c1 activates with no fault.
  val noCleanActivation = not(Q::s.faults == 0 and Q::isActive(Q::s, "c1"))

  // The repeat-then-rekey fixture: a re-key while client c1's CONFIRM repeat
  // count is positive, which the re-key resets with the pending handshake.
  val noRekeyAfterRepeat = not(repeated and Q::last.act == "rekey")

  // The reopen-window fixture: the owner activated a reopened client's new
  // handshake before its READY reached the client, which still holds the
  // replaced session.
  val noReopenWindow = not(Q::witnessReopenWindow)
}
