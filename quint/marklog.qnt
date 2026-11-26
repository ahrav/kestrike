/// The watermark's file log under in-place raises, whole replacements and crashes: one client process at a time
/// reads coverage pages 1 to 3 in batches, another writer advances them, and the log file holds one slot per mark.
/// A page's value is its version, from 1 to 3. Each step is one batch of reads, one batch whose log write a crash
/// interrupts, one write by the other writer, or a restart.
module marklog {
  const BOUND: int
  type Slot = {key: int, ver: int}
  type Event = {act: str, how: str}
  /// The store's version of each page.
  var store: int -> int
  /// The log file's slots in slot order; key 0 is a free slot.
  var file: List[Slot]
  /// The watermark the client process holds: each page's version, 0 for no mark.
  var mark: int -> int
  /// The watermark of the last call that returned.
  var acked: int -> int
  /// The watermark before and after the log write a crash interrupted, when the last step was that crash.
  var before: int -> int
  var after: int -> int
  var ev: Event
  var turn: int
  pure val PAGES = Set(1, 2, 3)
  pure val VERSIONS = 3
  pure val SLOTS = 6
  pure val NONE = PAGES.mapBy(_ => 0)
  pure val FREE = {key: 0, ver: 0}
  /// The marks a file holds.
  pure def marksOf(slots: List[Slot]): int -> int =
    PAGES.mapBy(k => slots.foldl(0, (held, s) => if (s.key == k) s.ver else held))
  /// The file a whole replacement writes: the marks in key order, then free slots.
  pure def whole(marks: int -> int): List[Slot] = {
    val held = [1, 2, 3].select(k => marks.get(k) > 0).foldl([], (out, k) => out.append({key: k, ver: marks.get(k)}))
    0.to(SLOTS - 1).fold(held, (out, i) => if (out.length() < SLOTS) out.append(FREE) else out)
  }
  /// The slot an in-place raise of the batch `rising` writes key `k` to: the slot that holds it, or for a new key
  /// the first free slot, the new batch of one raise taking consecutive slots in key order.
  pure def slotOf(slots: List[Slot], rising: Set[int], k: int): int = {
    val at = slots.indices().filter(i => slots[i].key == k)
    val free = slots.indices().filter(i => slots[i].key == 0).fold(SLOTS, (a, i) => if (i < a) i else a)
    val earlier = rising.filter(j => j < k and slots.indices().forall(i => slots[i].key != j)).size()
    if (at.size() > 0) at.fold(0, (a, i) => i) else free + earlier
  }
  /// The file after an in-place raise of the batch `rising` to `marks` wrote the slots of `landed`.
  pure def inPlace(slots: List[Slot], marks: int -> int, rising: Set[int], landed: Set[int]): List[Slot] =
    [1, 2, 3].select(k => landed.contains(k)).foldl(slots, (out, k) =>
      out.replaceAt(slotOf(slots, rising, k), {key: k, ver: marks.get(k)}))
  action init = all {
    store' = PAGES.mapBy(_ => 1), file' = whole(NONE), mark' = NONE, acked' = NONE, before' = NONE, after' = NONE,
    ev' = {act: "init", how: ""}, turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// The marks a batch of reads of `batch` raises, and how the log makes them durable: in place when at most one of
  /// them is new, and by a whole replacement otherwise.
  def raised(batch: Set[int]): Set[int] = batch.filter(k => store.get(k) > mark.get(k))
  def inPlaceRaise(batch: Set[int]): bool = raised(batch).filter(k => mark.get(k) == 0).size() <= 1
  def risen(batch: Set[int]): int -> int = PAGES.mapBy(k => if (raised(batch).contains(k)) store.get(k) else mark.get(k))
  /// The client reads the pages of `batch` in one batch, and the log records the raised marks before the call returns.
  action read(batch: Set[int]): bool = all {
    tick, batch.size() > 0,
    mark' = risen(batch), acked' = risen(batch),
    file' = if (raised(batch).size() == 0) file
      else if (inPlaceRaise(batch)) inPlace(file, risen(batch), raised(batch), raised(batch)) else whole(risen(batch)),
    store' = store, before' = NONE, after' = NONE,
    ev' = {act: "read", how: if (raised(batch).size() == 0) "none" else if (inPlaceRaise(batch)) "inPlace" else "whole"}
  }
  /// The process dies in the log write of a batch that raises marks: an in-place raise leaves the slots of `landed`
  /// written and the others as they were, and a whole replacement leaves the previous file or the new one. The
  /// next process loads the file.
  action crash(batch: Set[int], landed: Set[int]): bool = {
    val torn = if (inPlaceRaise(batch)) inPlace(file, risen(batch), raised(batch), landed)
      else if (landed == raised(batch)) whole(risen(batch)) else file
    all {
      tick, raised(batch).size() > 0, landed.subseteq(raised(batch)),
      inPlaceRaise(batch) or landed == Set() or landed == raised(batch),
      file' = torn, mark' = marksOf(torn), acked' = acked, before' = mark, after' = risen(batch), store' = store,
      ev' = {act: "crash", how: if (inPlaceRaise(batch)) "inPlace" else "whole"}
    }
  }
  /// The other writer advances a page.
  action write(k: int): bool = all {
    tick, store.get(k) < VERSIONS,
    store' = store.set(k, store.get(k) + 1),
    file' = file, mark' = mark, acked' = acked, before' = NONE, after' = NONE, ev' = {act: "write", how: ""}
  }
  /// The process ends between calls and the next one loads the file.
  action restart = all {
    tick,
    mark' = marksOf(file), file' = file, acked' = acked, store' = store, before' = NONE, after' = NONE,
    ev' = {act: "restart", how: ""}
  }
  action step = any {
    {
      nondet batch = PAGES.powerset().oneOf()
      read(batch)
    },
    {
      nondet batch = PAGES.powerset().oneOf()
      nondet landed = PAGES.powerset().oneOf()
      crash(batch, landed)
    },
    {
      nondet k = PAGES.oneOf()
      write(k)
    },
    restart,
  }
  /// The marks fill a prefix of the slots: no mark follows a free slot.
  val MarksFillPrefix = file.indices().forall(i => i == 0 or file[i].key == 0 or file[i - 1].key != 0)
  /// No two slots hold one key.
  val OneSlotPerKey = file.indices().forall(i => file.indices().forall(j => i == j or file[i].key == 0
    or file[i].key != file[j].key))
  /// After a crash, the file loads each mark as it was before the interrupted write or as that write made it.
  val LoadsBeforeOrAfter = ev.act != "crash" or PAGES.forall(k => mark.get(k) == before.get(k)
    or mark.get(k) == after.get(k))
  /// The file holds every mark at or above the watermark of the last call that returned, and the client's
  /// watermark is the file's.
  val ReturnedMarksAreDurable = PAGES.forall(k => marksOf(file).get(k) >= acked.get(k)) and mark == marksOf(file)
  val safety = MarksFillPrefix and OneSlotPerKey and LoadsBeforeOrAfter and ReturnedMarksAreDurable
  val witnessFirstMark = ev.act == "read" and ev.how == "inPlace" and file[0].key != 0 and file[1].key == 0
  val witnessRaisedInPlace = ev.act == "read" and ev.how == "inPlace" and PAGES.exists(k => mark.get(k) > 1)
  val witnessTwoRaisedInPlace = ev.act == "read" and ev.how == "inPlace"
    and PAGES.filter(k => mark.get(k) > 1).size() >= 2
  val witnessWhole = ev.act == "read" and ev.how == "whole"
  val witnessNothingRaised = ev.act == "read" and ev.how == "none"
  val witnessOutOfKeyOrder = file[0].key > file[1].key and file[1].key != 0
  val witnessCrashNothingLanded = ev.act == "crash" and ev.how == "inPlace" and mark == before and after != before
  val witnessCrashPartlyLanded = ev.act == "crash" and ev.how == "inPlace" and mark != before and mark != after
  val witnessCrashAllLanded = ev.act == "crash" and ev.how == "inPlace" and mark == after and after != before
  val witnessCrashNewMarkLost = ev.act == "crash" and ev.how == "inPlace"
    and PAGES.exists(k => before.get(k) == 0 and after.get(k) > 0 and mark.get(k) == 0)
  val witnessCrashWholeOld = ev.act == "crash" and ev.how == "whole" and mark == before
  val witnessCrashWholeNew = ev.act == "crash" and ev.how == "whole" and mark == after
  val witnessWrite = ev.act == "write"
  val witnessRestart = ev.act == "restart" and PAGES.exists(k => mark.get(k) > 0)
}
