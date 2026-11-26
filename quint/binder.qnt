/// Two binders, 0 and 1, bind and release an NVMe controller, device 0, and an ENI, device 1. Each binder owns one
/// state directory with one record. A step is one action of one binder: an owner or device lock, a record
/// consultation, a record write or removal, one sysfs driver write, one group guard or one network command. `crash`
/// kills a binder between steps: its record, the drivers and the network state stay, and its locks and guards are
/// freed. `LOCK_GAP` frees a binder's device locks after its consultation, and `COOPERATING` holds each pair
/// `(a, b)` in which binder `a` consults binder `b`'s record.
///
/// `pc` is each binder's next step. A bind runs 1 (preflight), 2 and 3 (device locks), 4 (consultation), 15 (next
/// hops, with the ENI), 5 (record write), `6 + 4 * d` to `9 + 4 * d` for each requested device `d` (second capture,
/// override, unbind, vfio-pci bind) and 14 (return). A release runs 20 (record read), 21 and 22 (device locks), 23
/// (consultation), 24 and 25 (group guards), `26 + 4 * d` to `29 + 4 * d` (unbind, override, bind, original
/// override), 34 (four network commands), 35 (record removal) and 36 (return). A refused second capture or driver
/// write rolls back from `40 + 4 * d` to `43 + 4 * d`, then 48 (network commands), 49 (record removal) and 50
/// (return). A restore or rollback of a device starts at the write its driver state needs.
///
/// A driver is 0 on the kernel driver, 1 unbound and 2 on vfio-pci. An override is 0 as found, 2 for vfio-pci and 3
/// for the kernel driver's name. A raw record is 0 when absent, 1 naming the controller, 2 the ENI and 3 both.
/// `network` has one bit for each of the ENI's MTU, link state, address and route, restored by the four network
/// commands in that order, and bit 16 for its resolved next hops.
module binder {
  const LOCK_GAP: bool
  const COOPERATING: Set[(int, int)]
  type State = {
    pc: List[int], owner: List[bool], requests: List[Set[int]], moved: List[Set[int]], locks: List[int],
    guards: List[int], present: List[bool], records: List[Set[int]], rawRecords: List[int], driver: List[int],
    overrides: List[int], network: int, networkPart: List[int], releasedNames: List[Set[int]],
    releaseWrites: Set[(int, int)], outcome: str
  }
  /// The last action and its inputs: `device` is -1 and `requested` empty where the action takes none, and
  /// `accept` is true where the action takes no fault input.
  type Last = { act: str, binder: int, device: int, requested: Set[int], accept: bool }
  var st: State
  var last: Last
  var turn: int
  pure val ACTORS = Set(0, 1)
  pure val DEVICES = Set(0, 1)
  pure val NETWORK = 31
  pure def rawRecord(names: Set[int]): int = if (names == Set(0, 1)) 3 else if (names.contains(0)) 1 else 2
  pure def rawNames(code: int): Set[int] =
    if (code == 3) Set(0, 1) else if (code == 1) Set(0) else if (code == 2) Set(1) else Set()
  pure def restoreNetwork(state: int, part: int): int = {
    val bit = if (part == 0) 1 else if (part == 1) 2 else if (part == 2) 4 else 8
    if ((state / bit) % 2 == 0) state + bit else state
  }
  pure def freed(holders: List[int], a: int): List[int] =
    holders.foldl([], (xs, holder) => xs.append(if (holder == a) -1 else holder))

  action init = all {
    st' = {
      pc: [0, 0], owner: [false, false], requests: [Set(), Set()], moved: [Set(), Set()], locks: [-1, -1],
      guards: [-1, -1], present: [false, false], records: [Set(), Set()], rawRecords: [0, 0], driver: [0, 0],
      overrides: [0, 0], network: NETWORK, networkPart: [0, 0], releasedNames: [Set(), Set()],
      releaseWrites: Set(), outcome: ""
    },
    last' = { act: "init", binder: -1, device: -1, requested: Set(), accept: true },
    turn' = 0
  }

  def otherRecords(a: int): Set[int] = ACTORS.filter(b => b != a and COOPERATING.contains((a, b)))
    .fold(Set(), (names, b) => names.union(st.records.nth(b)))
  /// Binder `a` at step `pc`. `outcome` is the outcome the action reports and is empty unless the action sets one.
  def at(a: int, pc: int): State = { ...st, pc: st.pc.replaceAt(a, pc), outcome: "" }
  /// The binder's call ends: its process holds no lock and no guard, and what the process kept of the call ends
  /// with it: its request, the devices it moved, its count modulo four of network commands and its release's names
  /// and writes.
  def finished(a: int, outcome: str): State = {
    ...at(a, 0), owner: st.owner.replaceAt(a, false), locks: freed(st.locks, a), guards: freed(st.guards, a),
    requests: st.requests.replaceAt(a, Set()), moved: st.moved.replaceAt(a, Set()),
    networkPart: st.networkPart.replaceAt(a, 0), releasedNames: st.releasedNames.replaceAt(a, Set()),
    releaseWrites: st.releaseWrites.filter(pair => pair._1 != a), outcome: outcome
  }
  def firstDevice(a: int): int = if (st.requests.nth(a).contains(0)) 0 else 1
  def restorePc(d: int, rollback: bool): int = (if (rollback) 40 else 26) + 4 * d +
    (if (st.driver.nth(d) == 2) 0 else if (st.driver.nth(d) == 1) 1 else 3)
  def rollbackPc(moved: Set[int]): int =
    if (moved.contains(0)) restorePc(0, true) else if (moved.contains(1)) restorePc(1, true) else 49
  def guardPc(a: int): int =
    if (st.requests.nth(a).contains(0) and st.driver.nth(0) == 2) 24
    else if (st.requests.nth(a).contains(1) and st.driver.nth(1) == 2) 25
    else restorePc(firstDevice(a), false)
  def released(a: int, d: int): Set[(int, int)] = st.releaseWrites.union(Set((a, d)))

  action commit(after: State, act: str, a: int, d: int, requested: Set[int], accept: bool): bool = all {
    st' = after,
    last' = { act: act, binder: a, device: d, requested: requested, accept: accept }
  }
  action bindOwner(a: int, requested: Set[int]): bool = all {
    st.pc.nth(a) == 0, not(st.owner.nth(a)),
    commit({ ...at(a, 1), owner: st.owner.replaceAt(a, true), requests: st.requests.replaceAt(a, requested) },
      "bindOwner", a, -1, requested, true)
  }
  action bindPreflight(a: int, accept: bool): bool = all {
    st.pc.nth(a) == 1,
    commit(if (accept and not(st.present.nth(a)) and st.requests.nth(a).forall(d => st.driver.nth(d) == 0))
        at(a, 2 + firstDevice(a))
      else finished(a, "preflight-refused"), "bindPreflight", a, -1, Set(), accept)
  }
  action bindDeviceLock(a: int, d: int): bool = all {
    st.pc.nth(a) == 2 + d, st.requests.nth(a).contains(d),
    commit(if (st.locks.nth(d) == -1)
        { ...at(a, if (d == 0 and st.requests.nth(a).contains(1)) 3 else 4), locks: st.locks.replaceAt(d, a) }
      else finished(a, "contention-refused"), "bindDeviceLock", a, d, Set(), true)
  }
  action consultRecords(a: int): bool = all {
    st.pc.nth(a) == 4,
    commit(if (otherRecords(a).intersect(st.requests.nth(a)) == Set())
        { ...at(a, if (st.requests.nth(a).contains(1)) 15 else 5),
          locks: if (LOCK_GAP) freed(st.locks, a) else st.locks }
      else finished(a, "other-owner-refused"), "consultRecords", a, -1, Set(), true)
  }
  action resolveHops(a: int): bool = all {
    st.pc.nth(a) == 15,
    commit({ ...at(a, 5), network: if (st.network < 16) st.network + 16 else st.network },
      "resolveHops", a, -1, Set(), true)
  }
  action publish(a: int): bool = all {
    st.pc.nth(a) == 5,
    commit({ ...at(a, 6 + 4 * firstDevice(a)), present: st.present.replaceAt(a, true),
      records: st.records.replaceAt(a, st.requests.nth(a)),
      rawRecords: st.rawRecords.replaceAt(a, rawRecord(st.requests.nth(a))), outcome: "published" },
      "publish", a, -1, Set(), true)
  }
  action secondCapture(a: int, d: int, accept: bool): bool = all {
    st.pc.nth(a) == 6 + 4 * d,
    commit(if (accept and st.driver.nth(d) == 0 and st.overrides.nth(d) == 0) at(a, 7 + 4 * d)
      else { ...at(a, rollbackPc(st.moved.nth(a))), outcome: "second-capture-refused" },
      "secondCapture", a, d, Set(), accept)
  }
  /// The override write names the device moved. Under `LOCK_GAP` the write retakes the device lock and is refused
  /// while the other binder holds it.
  action setOverride(a: int, d: int, accept: bool): bool = {
    val moved = st.moved.nth(a).union(Set(d))
    all {
      st.pc.nth(a) == 7 + 4 * d,
      commit(if (not(accept) or (st.locks.nth(d) != a and st.locks.nth(d) != -1))
          { ...at(a, rollbackPc(moved)), moved: st.moved.replaceAt(a, moved), outcome: "driver-refused" }
        else { ...at(a, 8 + 4 * d), moved: st.moved.replaceAt(a, moved), locks: st.locks.replaceAt(d, a),
          overrides: st.overrides.replaceAt(d, 2) }, "setOverride", a, d, Set(), accept)
    }
  }
  action unbind(a: int, d: int, accept: bool): bool = all {
    st.pc.nth(a) == 8 + 4 * d,
    commit(if (not(accept)) { ...at(a, rollbackPc(st.moved.nth(a))), outcome: "driver-refused" }
      else { ...at(a, 9 + 4 * d), driver: st.driver.replaceAt(d, 1), network: if (d == 1) 0 else st.network },
      "unbind", a, d, Set(), accept)
  }
  action vfioBind(a: int, d: int, accept: bool): bool = all {
    st.pc.nth(a) == 9 + 4 * d,
    commit(if (not(accept)) { ...at(a, rollbackPc(st.moved.nth(a))), outcome: "driver-refused" }
      else { ...at(a, if (d == 0 and st.requests.nth(a).contains(1)) 10 else 14), driver: st.driver.replaceAt(d, 2),
        locks: if (LOCK_GAP and st.locks.nth(d) == a) st.locks.replaceAt(d, -1) else st.locks },
      "vfioBind", a, d, Set(), accept)
  }
  action bindReturn(a: int): bool = all {
    st.pc.nth(a) == 14, commit(finished(a, "bound"), "bindReturn", a, -1, Set(), true)
  }
  action crash(a: int): bool = all {
    st.pc.nth(a) != 0,
    commit(finished(a, if (st.present.nth(a)) "crash-after-publish" else "crash-before-publish"),
      "crash", a, -1, Set(), true)
  }
  /// A second invocation for an owner whose lock a live invocation holds.
  action liveOwnerRefusal(a: int): bool = all {
    st.pc.nth(a) != 0, st.owner.nth(a),
    commit({ ...st, outcome: "live-owner-refused" }, "liveOwnerRefusal", a, -1, Set(), true)
  }
  action releaseOwner(a: int): bool = all {
    st.pc.nth(a) == 0, not(st.owner.nth(a)),
    commit({ ...at(a, 20), owner: st.owner.replaceAt(a, true) }, "releaseOwner", a, -1, Set(), true)
  }
  /// The release restores the devices its raw record decodes to.
  action readRecord(a: int): bool = all {
    st.pc.nth(a) == 20,
    commit(if (st.present.nth(a))
        { ...at(a, 21 + (if (st.records.nth(a).contains(0)) 0 else 1)),
          requests: st.requests.replaceAt(a, st.records.nth(a)),
          releasedNames: st.releasedNames.replaceAt(a, rawNames(st.rawRecords.nth(a))) }
      else finished(a, "fresh-release-refuses-missing"), "readRecord", a, -1, Set(), true)
  }
  action releaseDeviceLock(a: int, d: int): bool = all {
    st.pc.nth(a) == 21 + d, st.requests.nth(a).contains(d),
    commit(if (st.locks.nth(d) == -1)
        { ...at(a, if (d == 0 and st.requests.nth(a).contains(1)) 22 else 23), locks: st.locks.replaceAt(d, a) }
      else finished(a, "contention-refused"), "releaseDeviceLock", a, d, Set(), true)
  }
  action releaseConsult(a: int): bool = all {
    st.pc.nth(a) == 23,
    commit(if (otherRecords(a).intersect(st.requests.nth(a)) == Set()) at(a, guardPc(a))
      else finished(a, "other-owner-refused"), "releaseConsult", a, -1, Set(), true)
  }
  action groupGuard(a: int, d: int, accept: bool): bool = all {
    st.pc.nth(a) == 24 + d, st.requests.nth(a).contains(d), st.driver.nth(d) == 2,
    commit(if (accept)
        { ...at(a, if (d == 0 and st.requests.nth(a).contains(1) and st.driver.nth(1) == 2) 25
            else restorePc(firstDevice(a), false)), guards: st.guards.replaceAt(d, a) }
      else finished(a, "guard-refused"), "groupGuard", a, d, Set(), accept)
  }
  /// A release unbinds a device from vfio-pci only under the device's group guard.
  action restoreUnbind(a: int, d: int): bool = all {
    st.pc.nth(a) == 26 + 4 * d, st.guards.nth(d) == a,
    commit({ ...at(a, 27 + 4 * d), driver: st.driver.replaceAt(d, 1), network: if (d == 1) 0 else st.network,
      releaseWrites: released(a, d) }, "restoreUnbind", a, d, Set(), true)
  }
  action restoreOverride(a: int, d: int): bool = all {
    st.pc.nth(a) == 27 + 4 * d,
    commit({ ...at(a, 28 + 4 * d), overrides: st.overrides.replaceAt(d, 3), releaseWrites: released(a, d) },
      "restoreOverride", a, d, Set(), true)
  }
  action restoreBind(a: int, d: int): bool = all {
    st.pc.nth(a) == 28 + 4 * d,
    commit({ ...at(a, 29 + 4 * d), driver: st.driver.replaceAt(d, 0), releaseWrites: released(a, d) },
      "restoreBind", a, d, Set(), true)
  }
  action restoreOriginalOverride(a: int, d: int): bool = all {
    st.pc.nth(a) == 29 + 4 * d,
    commit({ ...at(a, if (d == 0 and st.requests.nth(a).contains(1)) restorePc(1, false)
        else if (st.requests.nth(a).contains(1)) 34 else 35),
      overrides: st.overrides.replaceAt(d, 0), releaseWrites: released(a, d) },
      "restoreOriginalOverride", a, d, Set(), true)
  }
  def networkStep(a: int, pc: int): State = {
    val part = st.networkPart.nth(a)
    { ...at(a, if (part == 3) pc + 1 else pc), network: restoreNetwork(st.network, part),
      networkPart: st.networkPart.replaceAt(a, if (part == 3) 0 else part + 1) }
  }
  action networkBatch(a: int): bool = all {
    st.pc.nth(a) == 34, commit(networkStep(a, 34), "networkBatch", a, -1, Set(), true)
  }
  /// A release drops its guards with its record; a rollback holds none.
  action unlink(a: int): bool = all {
    Set(35, 49).contains(st.pc.nth(a)),
    commit({ ...at(a, st.pc.nth(a) + 1), present: st.present.replaceAt(a, false),
      records: st.records.replaceAt(a, Set()), rawRecords: st.rawRecords.replaceAt(a, 0),
      guards: if (st.pc.nth(a) == 35) freed(st.guards, a) else st.guards }, "unlink", a, -1, Set(), true)
  }
  action releaseReturn(a: int): bool = all {
    st.pc.nth(a) == 36, commit(finished(a, "fresh-release-restores"), "releaseReturn", a, -1, Set(), true)
  }
  action rollbackUnbind(a: int, d: int): bool = all {
    st.pc.nth(a) == 40 + 4 * d,
    commit({ ...at(a, 41 + 4 * d), driver: st.driver.replaceAt(d, 1), network: if (d == 1) 0 else st.network },
      "rollbackUnbind", a, d, Set(), true)
  }
  action rollbackOverride(a: int, d: int): bool = all {
    st.pc.nth(a) == 41 + 4 * d,
    commit({ ...at(a, 42 + 4 * d), overrides: st.overrides.replaceAt(d, 3) }, "rollbackOverride", a, d, Set(), true)
  }
  action rollbackBind(a: int, d: int): bool = all {
    st.pc.nth(a) == 42 + 4 * d,
    commit({ ...at(a, 43 + 4 * d), driver: st.driver.replaceAt(d, 0) }, "rollbackBind", a, d, Set(), true)
  }
  action rollbackOriginalOverride(a: int, d: int): bool = all {
    st.pc.nth(a) == 43 + 4 * d,
    commit({ ...at(a, if (d == 0 and st.moved.nth(a).contains(1)) restorePc(1, true)
        else if (st.moved.nth(a).contains(1)) 48 else 49), overrides: st.overrides.replaceAt(d, 0) },
      "rollbackOriginalOverride", a, d, Set(), true)
  }
  action rollbackNetworkBatch(a: int): bool = all {
    st.pc.nth(a) == 48, commit(networkStep(a, 48), "rollbackNetworkBatch", a, -1, Set(), true)
  }
  action rollbackReturn(a: int): bool = all {
    st.pc.nth(a) == 50, commit(finished(a, "rolled-back"), "rollbackReturn", a, -1, Set(), true)
  }

  /// Every action of either binder over its whole input domain. `turn` stays 0, so the reachable states are
  /// finite.
  action step = all {
    turn' = turn,
    any {
      { nondet a = ACTORS.oneOf()
        nondet requested = Set(Set(0), Set(1), Set(0, 1)).oneOf()
        bindOwner(a, requested) },
      { nondet a = ACTORS.oneOf()
        nondet accept = Set(false, true).oneOf()
        bindPreflight(a, accept) },
      { nondet a = ACTORS.oneOf()
        any { consultRecords(a), resolveHops(a), publish(a), bindReturn(a), crash(a), liveOwnerRefusal(a),
          releaseOwner(a), readRecord(a), releaseConsult(a), networkBatch(a), unlink(a), releaseReturn(a),
          rollbackNetworkBatch(a), rollbackReturn(a) } },
      { nondet a = ACTORS.oneOf()
        nondet d = DEVICES.oneOf()
        any { bindDeviceLock(a, d), releaseDeviceLock(a, d), restoreUnbind(a, d), restoreOverride(a, d),
          restoreBind(a, d), restoreOriginalOverride(a, d), rollbackUnbind(a, d), rollbackOverride(a, d),
          rollbackBind(a, d), rollbackOriginalOverride(a, d) } },
      { nondet a = ACTORS.oneOf()
        nondet d = DEVICES.oneOf()
        nondet accept = Set(false, true).oneOf()
        any { secondCapture(a, d, accept), setOverride(a, d, accept), unbind(a, d, accept), vfioBind(a, d, accept),
          groupGuard(a, d, accept) } },
    }
  }

  /// A device leaves its kernel driver only while a present record names it.
  val RecordBeforeDriverExit = DEVICES.forall(d => st.driver.nth(d) == 0 or
    ACTORS.exists(a => st.present.nth(a) and st.records.nth(a).contains(d)))
  /// A device on vfio-pci is named by exactly one present record.
  val OneLiveRecordPerVfioDevice = DEVICES.forall(d => st.driver.nth(d) != 2 or
    ACTORS.filter(a => st.present.nth(a) and st.records.nth(a).contains(d)).size() == 1)
  /// Every restore write of a release names a device its own raw record decodes to.
  val ReleaseRestoresOwnRecordOnly =
    st.releaseWrites.forall(pair => st.releasedNames.nth(pair._1).contains(pair._2))
  val safety = RecordBeforeDriverExit and OneLiveRecordPerVfioDevice and ReleaseRestoresOwnRecordOnly
}
