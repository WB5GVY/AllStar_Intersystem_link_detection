"""Offline end-to-end exercise of run_scan() with phase-2 listeners:
fake API (graph_analyzer selftest payloads), stub notifier/disconnector,
REAL LinkWatcher (not started) + REAL StatusCollector on a scratch DB,
fake rpt_reader snapshot. No network, no SSH, no email, no live DBs."""
import os
import sys
import tempfile
import time
import types

W = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, W)
os.chdir(W)

import asl_link_detector as D              # noqa: E402
import graph_analyzer as G                 # noqa: E402
from asl_api import ASLApiClient           # noqa: E402
from link_watch import LinkWatcher         # noqa: E402
from status_server import StatusCollector  # noqa: E402
from listener_notice import ListenerNotice # noqa: E402

td = tempfile.mkdtemp()


def rec(name, allstar=True):
    d = {"name": name}
    if allstar:
        d.update({"Node_ID": 1, "callsign": f"C{name}", "server": {"Location": "X"},
                  "regseconds": 1})
    return d


PAYLOADS = {
    1000: ("T2000,T3000", [rec(2000), rec(3000)]),
    2000: ("T1000,T4000", [rec(1000), rec(4000)]),
    3000: ("T1000", [rec(1000)]),
    4000: ("R2000,R5000,L6000", [rec(2000), rec(5000), rec(6000)]),
    5000: ("", []), 6000: ("", []),
}
client = ASLApiClient()
client.get_node_stats = lambda n: {"stats": {"data": {
    "nodes": PAYLOADS.get(n, ("", []))[0],
    "linkedNodes": PAYLOADS.get(n, ("", []))[1]}}}
G.check_node_dns = lambda n: types.SimpleNamespace(
    is_registered=True, ip_address="192.0.2.1", port=4569)


class StubNotifier:
    _email_healthy = True
    _qrz_healthy = True
    _last_email_send = None
    qrz = None
    rate_limits = {}
    def __init__(self):
        self.sent = []
        self.notified = 0
        self.tracker = types.SimpleNamespace(
            is_rate_limited=lambda *a, **k: False,
            record_pending_simple=lambda *a, **k: None,
            notification_count_today=lambda *a, **k: 0)
    def is_quiet_hours(self):
        return False
    def report_error(self, *a, **k):
        return True
    def notify(self, *a, **k):
        self.notified += 1
        return 0
    def send_listener_notice(self, listeners, mesh_count, unaccounted, system_count, hours,
                             allowance=None, suppressed_alerts=0):
        self.sent.append(dict(listeners=listeners, mesh_count=mesh_count,
                              unaccounted=unaccounted, system_count=system_count,
                              hours=hours, allowance=allowance,
                              suppressed_alerts=suppressed_alerts))
        return True
    def process_unusual_externals(self, result):
        return []
    def send_hidden_path_alert(self, **k):
        raise AssertionError("hidden-path alert must not fire")
    def send_watchdog_alert(self, *a, **k):
        return True


class StubDisc:
    managed_nodes = {}
    bridge_nodes = set()
    def __init__(self):
        self.attempts = []
    def attempt_disconnect(self, ev, **kw):
        self.attempts.append(ev)
        raise AssertionError("no disconnect expected for a listener")


class FakeSnap:
    def __init__(self, mesh):
        self.mesh_nodes = [str(m) for m in mesh]
        self.mesh_modes = {}
        self.mesh_count = len(mesh)
        self.reported_numlinks = len(mesh)
        self.adjacent = []
        self.errors = []
        self.vantage_node = 2000
        self.ok = True


class FakeReader:
    def __init__(self, mesh):
        self.snap = FakeSnap(mesh)
    def read(self, timeout_seconds=None):
        return self.snap


def run(permit, mesh):
    analyzer = G.GraphAnalyzer(client, focus_node=1000, bridge_nodes=[2000],
                               permit_listeners=permit)
    notifier = StubNotifier()
    disc = StubDisc()
    collector = StatusCollector(db_path=os.path.join(td, f"status_{permit}.db"))
    trips = []
    watcher = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25,
                                        "confirm_polls": 2}},
                          reader=FakeReader(mesh), disconnector=disc,
                          is_dry_run=lambda: False, on_trip=trips.append)
    ln = ListenerNotice(interval_hours=24)
    ok = D.run_scan(analyzer, notifier, disc, 1000, api_client=client,
                    collector=collector, dry_run=False,
                    enable_image_crosscheck=False, capturer=None,
                    analytics=None, rpt_reader=FakeReader(mesh), watcher=watcher,
                    bubble_gen=None, vantage_trust=None, listener_notice=ln)
    return ok, notifier, disc, collector, watcher, ln


checks = []
# The vantage mesh: system nodes + the listener + 130 outside entries behind it.
mesh = [1000, 2000, 3000, 4000, 5000, 6000] + list(range(700000, 700130))

ok, n, d, c, w, ln = run(True, mesh)
snap = c.get_snapshot()
checks += [
    ("permit on: scan returns", ok is not None),
    ("permit on: no violation notify, no disconnect", n.notified == 0 and not d.attempts),
    ("permit on: watcher listener set + allowance frozen at foreign count",
     w.listener_ids() == frozenset({4000}) and w._listener_allowance == 130),
    ("permit on: /status listeners block",
     snap["listeners"]["permitted"] is True
     and snap["listeners"]["present"][0]["node"] == 4000
     and sorted(snap["listeners"]["present"][0]["monitored"]) == [5000, 6000]),
    ("permit on: /status counts exclude monitored nodes",
     snap["topology"]["total_nodes"] == 4 and snap["node_counts"]["monitored_by_guest"] == 2
     and snap["node_counts"]["mesh_unaccounted"] == 130),
    ("permit on: notice sent once with counts", len(n.sent) == 1
     and n.sent[0]["mesh_count"] == 136 and n.sent[0]["unaccounted"] == 130
     and n.sent[0]["system_count"] == 4 and n.sent[0]["hours"] == 24),
    ("permit on: notice last-sent persisted", c.listener_notice_last_sent() is not None),
    ("permit on: watchdog status shows allowance",
     snap["link_watchdog"]["listener_allowance"] == 130
     if "link_watchdog" in snap else w.watchdog_status()["listener_allowance"] == 130),
]
# Second scan, same listener: notice must NOT repeat. Change 3: the mesh
# behind a listener's branches lands in the vantage table seconds AFTER the
# scan that first saw the branch, so inside the settle window the allowance
# may RISE to this scan's count (130 -> 131); after the window it is frozen.
ok2 = D.run_scan(G.GraphAnalyzer(client, 1000, [2000], permit_listeners=True), n, d, 1000,
                 api_client=client, collector=c, dry_run=False,
                 enable_image_crosscheck=False, rpt_reader=FakeReader(mesh + [800000]),
                 watcher=w, listener_notice=ln)
checks.append(("second scan: no repeat notice; allowance raised inside the settle window",
               len(n.sent) == 1 and w._listener_allowance == 131))
w._branches_changed_at = time.monotonic() - w.branch_settle_s - 1
D.run_scan(G.GraphAnalyzer(client, 1000, [2000], permit_listeners=True), n, d, 1000,
           api_client=client, collector=c, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh + [800000, 800001]),
           watcher=w, listener_notice=ln)
checks.append(("third scan after the settle window: same branches -> allowance frozen at 131",
               w._listener_allowance == 131))

# permit OFF with the same topology: violation path, no listener state.
ok, n0, d0, c0, w0, ln0 = run(False, mesh)
checks += [
    ("permit off: violations notified", n0.notified == 1),
    ("permit off: no listener state, no notice", w0.listener_ids() == frozenset()
     and not n0.sent and c0.get_snapshot()["listeners"]["present"] == []),
]

# --- Audit cases -------------------------------------------------------------
def scan(analyzer, notifier, disc, collector, watcher, ln, reader):
    return D.run_scan(analyzer, notifier, disc, 1000, api_client=client,
                      collector=collector, dry_run=False,
                      enable_image_crosscheck=False, rpt_reader=reader,
                      watcher=watcher, listener_notice=ln)


class NoSnapReader:
    """Models an SSH timeout: the real reader returns a snapshot with ok=False."""
    def read(self, timeout_seconds=None):
        s = FakeSnap([])
        s.ok = False
        s.errors = ["ssh timed out"]
        return s


# C1: first classification with NO vantage snapshot -> deferred, not allowance 0.
an = G.GraphAnalyzer(client, 1000, [2000], permit_listeners=True)
n1, d1 = StubNotifier(), StubDisc()
c1 = StatusCollector(db_path=os.path.join(td, "c1.db"))
w1 = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=NoSnapReader(), disconnector=d1, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
scan(an, n1, d1, c1, w1, ListenerNotice(24), NoSnapReader())
checks.append(("C1: no snapshot -> listener registration deferred, allowance untouched",
               w1.listener_ids() == frozenset() and w1._listener_allowance == 0))
scan(an, n1, d1, c1, w1, ListenerNotice(24), FakeReader(mesh))
checks.append(("C1: next scan with a snapshot registers with the real allowance",
               w1.listener_ids() == frozenset({4000}) and w1._listener_allowance == 130))

# C2: a scan where the listener's own fetch FAILS must keep it registered.
PAYLOADS_FAIL = dict(PAYLOADS)
client_fail = ASLApiClient()
client_fail.get_node_stats = lambda nid: (None if nid == 4000 else {"stats": {"data": {
    "nodes": PAYLOADS_FAIL.get(nid, ("", []))[0],
    "linkedNodes": PAYLOADS_FAIL.get(nid, ("", []))[1]}}})
an_fail = G.GraphAnalyzer(client_fail, 1000, [2000], permit_listeners=True)
scan(an_fail, n1, d1, c1, w1, ListenerNotice(24), FakeReader(mesh))
checks.append(("C2: listener unobserved (API error) -> stays registered, allowance frozen",
               w1.listener_ids() == frozenset({4000}) and w1._listener_allowance == 130
               and not d1.attempts))
# ...a scan where the BRIDGE's fetch fails (listener never reached) keeps it too.
client_bfail = ASLApiClient()
client_bfail.get_node_stats = lambda nid: (None if nid == 2000 else {"stats": {"data": {
    "nodes": PAYLOADS.get(nid, ("", []))[0],
    "linkedNodes": PAYLOADS.get(nid, ("", []))[1]}}})
scan(G.GraphAnalyzer(client_bfail, 1000, [2000], permit_listeners=True),
     n1, d1, c1, w1, ListenerNotice(24), FakeReader(mesh))
checks.append(("C2: bridge unobserved (listener unreached) -> stays registered",
               w1.listener_ids() == frozenset({4000}) and w1._listener_allowance == 130))
# ...and a scan where it is observed and has genuinely LEFT clears it.
PAYLOADS_GONE = dict(PAYLOADS); PAYLOADS_GONE[2000] = ("T1000", [rec(1000)])
client_gone = ASLApiClient()
client_gone.get_node_stats = lambda nid: {"stats": {"data": {
    "nodes": PAYLOADS_GONE.get(nid, ("", []))[0],
    "linkedNodes": PAYLOADS_GONE.get(nid, ("", []))[1]}}}
scan(G.GraphAnalyzer(client_gone, 1000, [2000], permit_listeners=True),
     n1, d1, c1, w1, ListenerNotice(24), FakeReader([1000, 2000, 3000]))
checks.append(("C2: listener gone (bridge no longer lists it) -> cleared",
               w1.listener_ids() == frozenset() and w1._listener_allowance == 0))

# C3: zero-branch listener must not freeze a pre-existing foreign count.
PAYLOADS_ZERO = dict(PAYLOADS); PAYLOADS_ZERO[4000] = ("R2000", [rec(2000)])
client_zero = ASLApiClient()
client_zero.get_node_stats = lambda nid: {"stats": {"data": {
    "nodes": PAYLOADS_ZERO.get(nid, ("", []))[0],
    "linkedNodes": PAYLOADS_ZERO.get(nid, ("", []))[1]}}}
n3, d3 = StubNotifier(), StubDisc()
c3 = StatusCollector(db_path=os.path.join(td, "c3.db"))
w3 = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=FakeReader(mesh), disconnector=d3, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
ghost_mesh = [1000, 2000, 3000, 4000] + list(range(900000, 900040))   # 40 ghosts
scan(G.GraphAnalyzer(client_zero, 1000, [2000], permit_listeners=True),
     n3, d3, c3, w3, ListenerNotice(24), FakeReader(ghost_mesh))
checks.append(("C3: zero-branch listener registered with allowance 0, no notice",
               w3.listener_ids() == frozenset({4000}) and w3._listener_allowance == 0
               and not n3.sent))
w3._roster_at = __import__("time").monotonic()
w3._process_watchdog([str(m) for m in ghost_mesh], __import__("time").monotonic())
w3._process_watchdog([str(m) for m in ghost_mesh], __import__("time").monotonic() + 1)
checks.append(("C3: pre-existing ghost wedge still trips the watchdog",
               not w3.watchdog_alarms.empty()))

# Attribution: listener AND a real offender on the same bridge -> offender cut, listener not.
PAYLOADS_TWO = dict(PAYLOADS)
PAYLOADS_TWO[2000] = ("T1000,T4000,T4500", [rec(1000), rec(4000), rec(4500)])
PAYLOADS_TWO[4500] = ("T2000,T5500", [rec(2000), rec(5500)])
PAYLOADS_TWO[5500] = ("", [])
client_two = ASLApiClient()
client_two.get_node_stats = lambda nid: {"stats": {"data": {
    "nodes": PAYLOADS_TWO.get(nid, ("", []))[0],
    "linkedNodes": PAYLOADS_TWO.get(nid, ("", []))[1]}}}


class CountingDisc(StubDisc):
    def attempt_disconnect(self, ev, **kw):
        self.attempts.append(ev.offending_node)
        return types.SimpleNamespace(success=True, action="disconnected",
                                     message="stub", skipped=False)


n4, d4 = StubNotifier(), CountingDisc()
c4 = StatusCollector(db_path=os.path.join(td, "c4.db"))
w4 = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=FakeReader(mesh), disconnector=d4, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
scan(G.GraphAnalyzer(client_two, 1000, [2000], permit_listeners=True),
     n4, d4, c4, w4, ListenerNotice(24), FakeReader(mesh + [4500, 5500]))
checks.append(("attribution: offender on the same bridge is cut, listener is not",
               d4.attempts and set(d4.attempts) == {4500}
               and w4.listener_ids() == frozenset({4000})
               and n4.notified == 1))

# Step 2 trigger B: the same listener, but the vantage saw it keyed -> the
# tracker vetoes it -> run_scan takes the violation path and CUTS it, the
# watcher's listener set is emptied (SIG-4), /status carries the veto.
from keyed_veto import KeyedVetoTracker
n5, d5 = StubNotifier(), CountingDisc()
n5.keyed_alerts = []
n5.send_keyed_listener_alert = lambda node, reason, strikes, already_vetoed=False: (
    n5.keyed_alerts.append((node, strikes)) or True)
c5 = StatusCollector(db_path=os.path.join(td, "c5.db"))
w5 = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=FakeReader(mesh), disconnector=d5, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
a5 = G.GraphAnalyzer(client, 1000, [2000], permit_listeners=True)
scan(a5, n5, d5, c5, w5, ListenerNotice(24), FakeReader(mesh))    # registers the listener
trips5 = []
kv5 = KeyedVetoTracker(lambda: a5, lambda: {"keyed_veto_enabled": True,
                                            "keyed_veto_ttl_seconds": 900,
                                            "keyed_veto_confirm_keyups": 2},
                       vantage_node=2000, on_trip=trips5.append,
                       notifier_getter=lambda: n5, listener_ids_getter=w5.listener_ids)
before = (w5.listener_ids(), len(d5.attempts))
kv5.on_keyed(4000, "2,3000TU,4000RK")
kv5.on_keyed(4000, "2,3000TU,4000RK")          # 30 s debounce lives in ami_listener
checks.append(("veto e2e: two keyups -> veto, one trip, one internal alert",
               4000 in a5.listener_veto and len(trips5) == 1 and n5.keyed_alerts == [(4000, 1)]
               and before == (frozenset({4000}), 0)))
D.run_scan(a5, n5, d5, 1000, api_client=client, collector=c5, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w5,
           listener_notice=ListenerNotice(24), veto_status=kv5.status)
snap5 = c5.get_snapshot()
checks += [
    ("veto e2e: vetoed listener is CUT through the normal violation path",
     d5.attempts and set(d5.attempts) == {4000} and n5.notified >= 1),
    ("veto e2e: watcher listener set emptied (SIG-4), allowance back to 0",
     w5.listener_ids() == frozenset() and w5._listener_allowance == 0),
    ("veto e2e: /status keyed_vetoes carries reason, strikes, deadlines",
     snap5["listeners"]["keyed_vetoes"].get("4000", {}).get("strikes") == 1
     and "keyed toward vantage 2000" in snap5["listeners"]["keyed_vetoes"]["4000"]["reason"]
     and snap5["listeners"]["keyed_vetoes"]["4000"]["hard_deadline"]),
    ("veto e2e: veto consulted by the scan (eligible to expire after TTL)",
     4000 in a5.listener_veto_seen),
]

# Step 2b: a DARK guest (registered in DNS, empty stats record) on bridge
# 2000 whose union shows foreign entries -> UNVERIFIED after 2 scans, one
# trustee notice, no cut; a K on bridge 2000's feed -> cut via
# watchdog_disconnect (reverify re-reads the union) + action email.
from dark_guest import DarkGuestTracker
PAYLOADS_DARK = dict(PAYLOADS)
PAYLOADS_DARK[4000] = ("", [])                       # dark: online (DNS stub says registered), no stats
client_dark = ASLApiClient()
client_dark.get_node_stats = lambda n: {"stats": {"data": {
    "nodes": PAYLOADS_DARK.get(n, ("", []))[0],
    "linkedNodes": PAYLOADS_DARK.get(n, ("", []))[1]}}}
unions = {2000: ["1000", "4000", "700001", "700002", "700003"]}

class DarkDisc(CountingDisc):
    managed_nodes = {2000: types.SimpleNamespace(enabled=True, node_id=2000)}
    bridge_nodes = {2000}
    def read_bridge_union(self, b):
        return unions.get(b)
    def watchdog_disconnect(self, bridge, target, reverify, reason):
        ok = reverify()
        self.attempts.append(("wd", bridge, target, ok))
        return types.SimpleNamespace(action="disconnected" if ok else "skipped_reverify",
                                     message="stub", success=ok)

n6, d6 = StubNotifier(), DarkDisc()
n6.dark_notices, n6.dark_actions = [], []
n6.send_dark_guest_notice = lambda rec: (n6.dark_notices.append(rec["node"]) or True)
n6.send_dark_guest_action = lambda rec, reason, action, msg: (n6.dark_actions.append((rec["node"], action)) or True)
c6 = StatusCollector(db_path=os.path.join(td, "c6.db"))
w6 = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=FakeReader(mesh), disconnector=d6, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
trips6 = []
dry6 = {"on": False}
cfg6 = {"enabled": True, "confirm_scans": 2, "notice_interval_hours": 24,
        "cut_on_keyed": True, "keyed_cut_cooldown_seconds": 120,
        "foreign_threshold": 3, "max_dark_guests": 3, "posting_grace_seconds": 3600}
# far end: 700001 posts a FRESH record that reports a link to the dark guest 4000
import time as _time
_fresh = rec(4000)
PAYLOADS_DARK[700001] = ("T4000", [_fresh])
_orig_stats = client_dark.get_node_stats
def _stats_with_time(n, _attempt=0):
    d = _orig_stats(n)
    if n == 700001:
        d["stats"]["data"]["time"] = int(_time.time())      # fresh post
    return d
client_dark.get_node_stats = _stats_with_time
dark6 = DarkGuestTracker(cfg_getter=lambda: cfg6,
                         disconnector_getter=lambda: d6, foreign_fn=w6.foreign_entries,
                         notifier_getter=lambda: n6, on_trip=trips6.append,
                         persist=c6.set_dark_guest_notices,
                         is_dry_run=lambda: dry6["on"],
                         allowance_fn=w6.listener_allowance,
                         own_nodes_fn=lambda: {1000, 2000},
                         attribute_fn=lambda g, f: D._dark_attribute(
                             client_dark, lambda: cfg6, g, f,
                             dns_check=lambda n: types.SimpleNamespace(is_registered=True)))
a6 = G.GraphAnalyzer(client_dark, 1000, [2000], permit_listeners=True)
# The dark guest's OFF-by-default record: `enabled` absent -> inert
dark_off = DarkGuestTracker(cfg_getter=lambda: {}, disconnector_getter=lambda: d6,
                            foreign_fn=w6.foreign_entries)
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark_off)
checks.append(("dark e2e: tracker without `enabled: true` stays inert through a scan",
               c6.get_snapshot()["dark_guests"]["nodes"] == {} and dark_off.watch_ids() == frozenset()))
for _ in range(2):
    D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
               enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
               listener_notice=ListenerNotice(24), dark_tracker=dark6)
snap6 = c6.get_snapshot()
r6 = a6.scan()
checks += [
    ("dark e2e: dark guest listed by the analyzer with the bridge's co-adjacent list, "
     "no violation, no cut",
     r6.dark_guests and r6.dark_guests[0]["node"] == 4000
     and r6.dark_guests[0]["co_adjacent"] == [1000]
     and n6.notified == 0 and d6.attempts == []),
    ("dark e2e: UNVERIFIED after 2 scans via ATTRIBUTED evidence (far end reports the "
     "link), one trustee notice, persisted, no co-guests",
     snap6["dark_guests"]["nodes"].get("4000", {}).get("state") == "unverified"
     and snap6["dark_guests"]["nodes"]["4000"]["evidence"] == "attributed"
     and snap6["dark_guests"]["nodes"]["4000"]["attributed"] == ["700001"]
     and snap6["dark_guests"]["nodes"]["4000"]["co_guests"] == []
     and n6.dark_notices == [4000] and "4000" in c6.dark_guest_notices()),
    ("dark e2e: K on another node's feed is ignored",
     dark6.on_keyed(4000, "1,4000TK", vantage=3000) is False and d6.attempts == []),
    ("dark e2e: K with no reporting vantage is ignored",
     dark6.on_keyed(4000, "1,4000TK") is False and d6.attempts == []),
]
dry6["on"] = True
checks.append(("dark e2e: monitor-only -> K on own bridge does NOT cut",
               dark6.on_keyed(4000, "1,4000TK", vantage=2000) is False and d6.attempts == []
               and trips6 == []))
dry6["on"] = False
checks.append(("dark e2e: the first K is an observation, not a cut (1/2)",
               dark6.on_keyed(4000, "1,4000TK", vantage=2000) is False and d6.attempts == []))
ok6 = dark6.on_keyed(4000, "1,4000TK", vantage=2000)
import time as _t; _t.sleep(0.3)
checks += [
    ("dark e2e: K on its own bridge -> reverify (union + far end) -> cut, action queued, trip",
     ok6 and d6.attempts == [("wd", 2000, 4000, True)] and n6.dark_actions == []
     and dark6.status()["pending_actions"] == 1 and len(trips6) == 1),
]
# membership routing (audit S1): the daemon's dispatcher sends a dark id to
# the dark tracker only; the veto tracker's own guard also refuses it.
from keyed_veto import KeyedVetoTracker as _KV
kv6 = _KV(lambda: a6, lambda: {"keyed_veto_enabled": True, "keyed_veto_confirm_keyups": 1},
          vantage_node=2000, listener_ids_getter=lambda: frozenset())
kv6.on_keyed(4000, "1,4000TK", vantage=2000)
checks.append(("dark e2e: a dark id never lands in the keyed-veto tracker",
               4000 not in a6.listener_veto and kv6.watch_ids() == frozenset()))
# third scan: notice not repeated; guest posting again -> record dropped
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark6)
checks.append(("dark e2e: no repeat notice within the interval; action email drained by the scan",
               n6.dark_notices == [4000] and n6.dark_actions == [(4000, "disconnected")]))
PAYLOADS_DARK[4000] = PAYLOADS[4000]
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark6)
checks.append(("dark e2e: guest starts posting -> dark record dropped, listener path takes over",
               c6.get_snapshot()["dark_guests"]["nodes"] == {} and w6.listener_ids() == frozenset({4000})))
# Change 1 (2026-09-08, a hub-attached guest): the guest POSTS a fresh record that
# reports ZERO links while the bridge still lists it -> linkless, never a
# dark-guest record, no notice, no cut, even across confirm_scans scans.
_linkless_fresh = {"on": False}
_stats_before_linkless = client_dark.get_node_stats
def _stats_linkless(n, _attempt=0):
    d = _stats_before_linkless(n)
    if n == 4000 and _linkless_fresh["on"]:
        d["stats"]["data"]["time"] = int(_time.time())
    return d
client_dark.get_node_stats = _stats_linkless
PAYLOADS_DARK[4000] = ("", [])
_linkless_fresh["on"] = True
_notices_before = list(n6.dark_notices)
# A FRESH tracker (no posting history for 4000) so the grace test below
# measures only what the linkless scans themselves credit (round-2 audit C1).
dark9 = DarkGuestTracker(cfg_getter=lambda: cfg6, disconnector_getter=lambda: d6,
                         foreign_fn=w6.foreign_entries, notifier_getter=lambda: n6,
                         allowance_fn=w6.listener_allowance, own_nodes_fn=lambda: {1000, 2000},
                         attribute_fn=lambda g, f: D._dark_attribute(
                             client_dark, lambda: cfg6, g, f,
                             dns_check=lambda n: types.SimpleNamespace(is_registered=True)))
for _ in range(3):
    D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
               enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
               listener_notice=ListenerNotice(24), dark_tracker=dark9)
r_lk = a6.scan()
checks += [
    ("linkless e2e: fresh empty guest record -> analyzer lists it linkless, not dark",
     [l["node"] for l in r_lk.linkless] == [4000] and r_lk.dark_guests == []
     and r_lk.linkless[0]["attached_to"] == 2000),
    ("linkless e2e: /status dark_guests.nodes stays empty over 3 scans; no notice; no cut",
     c6.get_snapshot()["dark_guests"]["nodes"] == {} and dark9.watch_ids() == frozenset()
     and n6.dark_notices == _notices_before
     and d6.attempts == [("wd", 2000, 4000, True)]),
    ("linkless e2e: /status `linkless` block lists the guest with its attach node and post age",
     [(x["node"], x["attached_to"], x["attachment"]) for x in c6.get_snapshot()["linkless"]]
     == [(4000, 2000, "bridge")]
     and isinstance(c6.get_snapshot()["linkless"][0]["post_age_seconds"], int)),
    # unchanged semantics: an empty record (fresh or not) is `unobserved`, so a
    # previously registered listener is KEPT, not disproved — exactly as
    # before change 1 (the node was dark+unobserved then, linkless+unobserved
    # now). A fresh scan never registers a NEW listener from an empty record.
    ("linkless e2e: prior listener registration retained (unobserved), none newly made",
     4000 in w6.listener_ids() and 4000 in r_lk.unobserved and r_lk.listeners == []),
]
# Change 2: the daemon's analytics hook writes one link_report_events row per
# non-reporting node per scan (the dict contract from ScanResult is pinned here).
from analytics_db import init_db as _an_init, Recorder as _Recorder
_an_conn = _an_init(os.path.join(td, "an.db"))
_an = {"recorder": _Recorder(_an_conn), "core": set(), "bridges": {2000}}
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark9, analytics=_an)
_an_rows = _an_conn.execute(
    "SELECT node_id, kind, attached_to, attachment, callsign, post_age_seconds "
    "FROM link_report_events").fetchall()
checks.append(("linkless e2e: analytics hook records the linkless guest (node, kind, bridge, "
               "attachment, callsign, integer post age)",
               len(_an_rows) == 1 and _an_rows[0][:4] == (4000, "linkless", 2000, "bridge")
               and _an_rows[0][4] == "C4000" and isinstance(_an_rows[0][5], int)))
# ... and the same guest with the post time gone -> dark again, and the three
# linkless scans earned NO posting-hiccup grace: evidence advances at once
# and the guest is UNVERIFIED after confirm_scans (2) scans (round-2 audit C1).
_linkless_fresh["on"] = False
_notices_before2 = list(n6.dark_notices)
for _ in range(2):
    D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
               enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
               listener_notice=ListenerNotice(24), dark_tracker=dark9)
_rec_back = c6.get_snapshot()["dark_guests"]["nodes"].get("4000") or {}
checks.append(("linkless e2e: post time gone -> dark again with NO grace from the linkless "
               "scans: UNVERIFIED after 2 scans, notice sent, /status linkless empty",
               _rec_back.get("state") == "unverified" and _rec_back.get("consecutive") == 2
               and "hiccup" not in str(_rec_back.get("note", ""))
               and n6.dark_notices == _notices_before2 + [4000]
               and c6.get_snapshot()["linkless"] == []))
PAYLOADS_DARK[4000] = PAYLOADS[4000]
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark9)
# A fresh-but-empty BRIDGE record must still degrade the scan (system node
# unobserved -> dark evidence not advanced), exactly like an untimed empty one.
PAYLOADS_DARK[2000] = ("", [])
_bridge_fresh = {"on": True}
_stats_before_bf = client_dark.get_node_stats
def _stats_bridge_fresh(n, _attempt=0):
    d = _stats_before_bf(n)
    if n == 2000 and _bridge_fresh["on"]:
        d["stats"]["data"]["time"] = int(_time.time())
    return d
client_dark.get_node_stats = _stats_bridge_fresh
dark8 = DarkGuestTracker(cfg_getter=lambda: cfg6, disconnector_getter=lambda: d6,
                         foreign_fn=w6.foreign_entries, notifier_getter=lambda: n6,
                         allowance_fn=w6.listener_allowance, own_nodes_fn=lambda: {1000, 2000})
r_bf = a6.scan()
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark8)
checks.append(("linkless e2e: a fresh-but-empty BRIDGE record -> unobserved, neither list, "
               "scan degraded for dark evidence",
               2000 in r_bf.unobserved and not r_bf.linkless and not r_bf.dark_guests
               and c6.get_snapshot()["dark_guests"]["degraded"] is not None))
_bridge_fresh["on"] = False
PAYLOADS_DARK[2000] = PAYLOADS[2000]
# _dark_attribute battery (audit 3 S5)
_now = int(_time.time())
def _mk_api(records, fail=(), post_time=None):
    post_time = post_time or {}
    class _A:
        post_age_seconds = staticmethod(ASLApiClient.post_age_seconds)
        def get_node_stats(self, n, _attempt=0):
            if n in fail:
                return None
            return {"stats": {"data": {"time": post_time.get(n, _now), "linkedNodes": []}}}
        def get_linked_node_details(self, n, data=None):
            if n in fail:
                return None
            return records.get(n, [])
    return _A()
_stale_post = {700003: _now - 10 * 3600, 700006: None}
_recs = {700001: [_fresh], 700002: [rec(5000)], 700003: [rec(4000)],
         700004: [{"name": "4000", "node_id": 4000, "is_external": True}],
         700005: [_fresh], 700006: [rec(4000)]}
# rec() gives name only; asl_api normally derives node_id — emulate that shape
for lst in _recs.values():
    for d in lst:
        d.setdefault("node_id", int(d["name"]) if str(d["name"]).isdigit() else 0)
        d.setdefault("is_external", False)
_dns_ok = lambda n: types.SimpleNamespace(is_registered=(n != 700005))
_cfgA = lambda: {"attribution_max_lookups": 3}
r = D._dark_attribute(_mk_api(_recs, post_time=_stale_post), _cfgA, 4000,
                      ["700001", "700002", "700003"], dns_check=_dns_ok)
checks.append(("attr: fresh far-end link counts; unrelated and STALE-POST records do not",
               r == ["700001"]))
r = D._dark_attribute(_mk_api(_recs, post_time=_stale_post), _cfgA, 4000,
                      ["700006"], dns_check=_dns_ok)
checks.append(("attr: a far-end record with no post time is not evidence", r == []))
r = D._dark_attribute(_mk_api(_recs), _cfgA, 4000, ["700004", "700005"], dns_check=_dns_ok)
checks.append(("attr: an external pseudo-link never matches; a far end NOT in DNS is ignored",
               r == []))
r = D._dark_attribute(_mk_api(_recs, fail=(700001, 700002)), _cfgA, 4000,
                      ["700001", "700002"], dns_check=_dns_ok)
checks.append(("attr: every lookup failed -> None (no evidence either way)", r is None))
r = D._dark_attribute(_mk_api(_recs, fail=(700002,)), _cfgA, 4000,
                      ["700002", "700001"], dns_check=_dns_ok)
checks.append(("attr: partial failure -> the successful matches", r == ["700001"]))
r = D._dark_attribute(_mk_api(_recs), _cfgA, 4000,
                      ["700002", "700003", "700002", "700001"], dns_check=_dns_ok)
checks.append(("attr: duplicates deduped; cap (3) still reaches the third distinct candidate",
               r == ["700003", "700001"]))
_b = [3]
D._dark_attribute(_mk_api(_recs), _cfgA, 4000, ["700002", "700003"], dns_check=_dns_ok, budget=_b)
r = D._dark_attribute(_mk_api(_recs), _cfgA, 4100, ["700001", "700002"], dns_check=_dns_ok, budget=_b)
checks.append(("attr: the budget is shared across guests in one scan", _b[0] == 0 and r == []))
r = D._dark_attribute(_mk_api(_recs), _cfgA, 4000,
                      ["3123456", "QQ0QQ", "700001"], exclude={"700001"}, dns_check=_dns_ok)
checks.append(("attr: EchoLink wire form, callsign tokens and excluded (own/allowlisted) ids skipped",
               r == []))
# audit 4 C-3: an EMPTY hub record must not replace the watcher's roster
_roster_before = w6._roster_ids
PAYLOADS_DARK[1000] = ("", [])
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark6)
checks.append(("C-3: empty hub record -> roster unchanged (the mesh does not become foreign)",
               w6._roster_ids == _roster_before and len(_roster_before) > 1))
PAYLOADS_DARK[1000] = PAYLOADS[1000]
# audit 2 C-C: a system node (the bridge) returning an empty record degrades the scan
PAYLOADS_DARK[4000] = ("", [])
PAYLOADS_DARK[2000] = ("", [])
dark7 = DarkGuestTracker(cfg_getter=lambda: cfg6, disconnector_getter=lambda: d6,
                         foreign_fn=w6.foreign_entries, notifier_getter=lambda: n6,
                         allowance_fn=w6.listener_allowance, own_nodes_fn=lambda: {1000, 2000})
D.run_scan(a6, n6, d6, 1000, api_client=client_dark, collector=c6, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=w6,
           listener_notice=ListenerNotice(24), dark_tracker=dark7)
checks.append(("dark e2e: bridge unobserved (empty record) -> dark evidence not advanced",
               c6.get_snapshot()["dark_guests"]["degraded"] is not None))
PAYLOADS_DARK[2000] = PAYLOADS[2000]

# --- Change 3 (2026-09-08) ---------------------------------------------------
# (a) A guest dialling an outside node (C) is neither cut nor a listener
#     branch; run_scan asks for ONE quick re-scan per new pair (cooldown).
PAYLOADS_C = dict(PAYLOADS)
PAYLOADS_C[4000] = ("R2000,C9000", [rec(2000), rec(9000)])
client_c = ASLApiClient()
client_c.get_node_stats = lambda n: {"stats": {"data": {
    "nodes": PAYLOADS_C.get(n, ("", []))[0],
    "linkedNodes": PAYLOADS_C.get(n, ("", []))[1]}}}
reqs = []
class CutDisc(StubDisc):
    managed_nodes = {2000: types.SimpleNamespace(enabled=True, node_id=2000)}
    bridge_nodes = {2000}
    def attempt_disconnect(self, ev, **kw):
        self.attempts.append(ev.offending_node)
        return types.SimpleNamespace(action="disconnected", message="stub", success=True,
                                     managed_node="2000", target_node=ev.offending_node)
nC, dC = StubNotifier(), CutDisc()
cC = StatusCollector(db_path=os.path.join(td, "cC.db"))
wC = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=FakeReader(mesh), disconnector=dC, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
aC = G.GraphAnalyzer(client_c, 1000, [2000], permit_listeners=True)
D._connecting_requested.clear(); D._connecting_last_global[0] = 0.0
_saved_delay = D._CONNECTING_RESCAN_DELAY_S
D._CONNECTING_RESCAN_DELAY_S = 0.2          # exercise the real Timer path, briefly
for _ in range(2):
    D.run_scan(aC, nC, dC, 1000, api_client=client_c, collector=cC, dry_run=False,
               enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=wC,
               listener_notice=ListenerNotice(24), scan_request=reqs.append)
_reqs_before_timer = len(reqs)
time.sleep(0.6)
D._CONNECTING_RESCAN_DELAY_S = _saved_delay
checks += [
    ("change 3 e2e: guest with a CONNECTING outside link -> no violation, no cut, listener "
     "with no branches", nC.notified == 0 and dC.attempts == []
     and wC.listener_ids() == frozenset({4000})),
    ("change 3 e2e: the re-scan request is DELAYED (timer), then exactly one for the pair "
     "across two scans (cooldown)",
     _reqs_before_timer == 0 and len(reqs) == 1 and "4000 -> 9000" in reqs[0]),
    ("change 3 e2e: /status connecting block lists the pair",
     [(x["node"], x["target"]) for x in cC.get_snapshot()["connecting"]] == [(4000, 9000)]),
]
# (b) The live 15:58 sequence: the registered listener flips to a real
#     transceive outside link -> violation -> cut -> watch entered, and the
#     STALE listener registration is revoked at once (the next poll must not
#     drop the watch); the complete scan then clears the listener set.
PAYLOADS_C[4000] = ("R2000,T9000", [rec(2000), rec(9000)])
PAYLOADS_C[9000] = ("T4000", [rec(4000)])
D.run_scan(aC, nC, dC, 1000, api_client=client_c, collector=cC, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=wC,
           listener_notice=ListenerNotice(24), scan_request=reqs.append)
checks.append(("change 3 e2e: listener flips to T outside -> cut, watch entered, listener "
               "registration gone, no watch dropped by a stale record",
               dC.attempts == [4000] and 4000 in wC._watches
               and wC.listener_ids() == frozenset() and wC._listener_allowance == 0))

# --- Coherence (2026-10-12) ---------------------------------------------------
# The shape of every real cut to date: the bridge lists the guest, the guest's
# OWN record names only the far node (a pre-join post served stale). No event,
# no cut, /status `unconfirmed`, ONE delayed re-look; once the record names
# the bridge too, the cut proceeds as before.
PAYLOADS_U = dict(PAYLOADS)
PAYLOADS_U[4000] = ("T9000", [rec(9000)])
PAYLOADS_U[9000] = ("T4000", [rec(4000)])
client_u = ASLApiClient()
client_u.get_node_stats = lambda n: {"stats": {"data": {
    "nodes": PAYLOADS_U.get(n, ("", []))[0],
    "linkedNodes": PAYLOADS_U.get(n, ("", []))[1]}}}
reqs_u = []
nU, dU = StubNotifier(), CutDisc()
cU = StatusCollector(db_path=os.path.join(td, "cU.db"))
wU = LinkWatcher({"watchdog": {"enabled": True, "foreign_threshold": 25, "confirm_polls": 2}},
                 reader=FakeReader(mesh), disconnector=dU, is_dry_run=lambda: False,
                 on_trip=lambda r: None)
aU = G.GraphAnalyzer(client_u, 1000, [2000], permit_listeners=True)
D._unconfirmed_requested.clear(); D._unconfirmed_last_global[0] = 0.0
for _ in range(2):
    D.run_scan(aU, nU, dU, 1000, api_client=client_u, collector=cU, dry_run=False,
               enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=wU,
               listener_notice=ListenerNotice(24), scan_request=reqs_u.append,
               coherence_cfg={"relook_delay_seconds": 0.2})
_ureqs_before_timer = len(reqs_u)
time.sleep(0.6)
_u_status = cU.get_snapshot()["unconfirmed"]
checks += [
    ("coherence e2e: guest on a pre-join record -> no violation, no cut, not a listener",
     nU.notified == 0 and dU.attempts == [] and wU.listener_ids() == frozenset()),
    ("coherence e2e: /status unconfirmed lists the guest with its outside node and raw record",
     [(x["node"], x["attached_to"], x["outside"], x["raw_nodes"]) for x in _u_status]
     == [(4000, 2000, [9000], "T9000")]),
    ("coherence e2e: ONE delayed re-look across two scans (node cooldown), via the timer",
     _ureqs_before_timer == 0 and len(reqs_u) == 1 and "4000" in reqs_u[0]),
]
PAYLOADS_U[4000] = ("T2000,T9000", [rec(2000), rec(9000)])
D.run_scan(aU, nU, dU, 1000, api_client=client_u, collector=cU, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh), watcher=wU,
           listener_notice=ListenerNotice(24), scan_request=reqs_u.append,
           coherence_cfg={"relook_delay_seconds": 0.2})
checks.append(("coherence e2e: the record names the bridge -> violation, cut, /status cleared",
               dU.attempts == [4000] and nU.notified >= 1
               and cU.get_snapshot()["unconfirmed"] == []))

# --- Three-state node health (2026-10-18) -------------------------------------
# The hub lists 2000 (T, a bridge) and 3000 (C: the hub is dialing it, 3000
# answers nothing and posts no stats); guest 5000 hangs T off bridge 2000.
# Letters come from the PARENT's record; a C link is listed yet NOT linked.
# Then a hub fetch FAILURE: node health is gated AND presence recording is
# skipped (the old code wrote a mass 'disappeared' + no-heartbeat scan).
from analytics_db import init_db as _nh_init_db, Recorder as _NHRecorder   # noqa: E402
from node_health import node_health_cfg as _nh_cfg, NodeHealthTracker as _NHTracker  # noqa: E402
_now_e = int(time.time())
PAYLOADS_NH = {1000: ("T2000,C3000", [rec(2000), rec(3000)]),
               2000: ("T1000,T5000", [rec(1000), rec(5000)]),
               3000: None,
               5000: ("T2000", [rec(2000)])}


def _nh_stats(n):
    p = PAYLOADS_NH.get(n, ("", []))
    if p is None:          # a record with an old registration and no stats post
        return {"node": {"regseconds": _now_e - 200000}, "stats": {}}
    return {"node": {"regseconds": _now_e - 30},
            "stats": {"data": {"time": _now_e - 10, "nodes": p[0], "linkedNodes": p[1]}}}


client_nh = ASLApiClient()
client_nh.get_node_stats = _nh_stats
_nh_conn = _nh_init_db(os.path.join(td, "nh_e2e.db"))
_nh_rec = _NHRecorder(_nh_conn)
_nh_analytics = {"recorder": _nh_rec, "core": {1000, 3000}, "bridges": {2000}}
_nh_tracker = _NHTracker(_nh_cfg({"focus_node": 1000, "node_health": {
    "enabled": True, "dns_lookups": False,
    "nodes": {1000: "self", 2000: 1000, 3000: 1000, 5000: 2000}}}), recorder=_nh_rec)
nH, dH = StubNotifier(), StubDisc()
cH = StatusCollector(db_path=os.path.join(td, "cH.db"))
for _ in range(2):
    D.run_scan(G.GraphAnalyzer(client_nh, 1000, [2000], permit_listeners=True), nH, dH, 1000,
               api_client=client_nh, collector=cH, dry_run=False,
               enable_image_crosscheck=False, rpt_reader=FakeReader(mesh),
               analytics=_nh_analytics, node_health=_nh_tracker)
_snapH = cH.get_snapshot()
_nhb = _snapH["node_health"]
_pres_before = _nh_conn.execute("SELECT COUNT(*) FROM current_presence").fetchone()[0]
_hb_before = _nh_conn.execute("SELECT COUNT(*) FROM scan_heartbeat").fetchone()[0]
_rows_before = _nh_conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0]
checks += [
    ("node health e2e: letters from the parent's record — 2000 T, 3000 C (listed, NOT linked), "
     "5000 T via 2000, hub self",
     _nhb["nodes"]["2000"]["letter"] == "T" and _nhb["nodes"]["3000"]["letter"] == "C"
     and _nhb["nodes"]["3000"]["linked"] is False and _nhb["nodes"]["5000"]["letter"] == "T"
     and _nhb["nodes"]["5000"]["parent"] == 2000 and _nhb["nodes"]["1000"]["letter"] == "self"),
    ("node health e2e: registered/posting from the records; 3000 neither",
     _nhb["nodes"]["2000"]["registered"] is True and _nhb["nodes"]["2000"]["posting"] is True
     and _nhb["nodes"]["3000"]["registered"] is False and _nhb["nodes"]["3000"]["posting"] is False),
    ("node health e2e: /status counts (linked 2/3 known, hub excluded) + node_counts keys",
     _nhb["counts"]["linked"] == 2 and _nhb["counts"]["linked_known"] == 3
     and _snapH["node_counts"]["linked"] == 2 and _snapH["node_counts"]["posting"] == 3),
    ("node health e2e: baseline rows (4 nodes x 3 facts) + 4 current rows; presence + heartbeat recorded",
     _rows_before == 12
     and _nh_conn.execute("SELECT COUNT(*) FROM current_node_health").fetchone()[0] == 4
     and _pres_before >= 3 and _hb_before >= 1),
]
client_fail = ASLApiClient()
client_fail.get_node_stats = lambda n: None if n == 1000 else _nh_stats(n)
D.run_scan(G.GraphAnalyzer(client_fail, 1000, [2000], permit_listeners=True), nH, dH, 1000,
           api_client=client_fail, collector=cH, dry_run=False,
           enable_image_crosscheck=False, rpt_reader=FakeReader(mesh),
           analytics=_nh_analytics, node_health=_nh_tracker)
_snapF = cH.get_snapshot()
checks.append(
    ("gate e2e: hub fetch failed -> presence NOT reconciled (no mass 'disappeared'), no new "
     "heartbeat, node health gated, no new rows",
     _nh_conn.execute("SELECT COUNT(*) FROM current_presence").fetchone()[0] == _pres_before
     and _nh_conn.execute("SELECT COUNT(*) FROM scan_heartbeat").fetchone()[0] == _hb_before
     and _snapF["node_health"]["scan_gated"] is True
     and all(v["gated"] for v in _snapF["node_health"]["nodes"].values())
     and _nh_conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0] == _rows_before))
_nh_conn.close()

import shutil
shutil.rmtree(td, ignore_errors=True)

failed = [nm for nm, okk in checks if not okk]
for nm, okk in checks:
    print(f"  [{'OK' if okk else 'FAIL'}] {nm}")
print(f"phase2 e2e: {len(checks) - len(failed)}/{len(checks)} passed")
sys.exit(1 if failed else 0)
