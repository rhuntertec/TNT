r"""SIP call flows out of one or two packet captures: the ladder, and what it says went wrong (SIP page, §3.28).

The Packet capture page rebuilds calls from the capture it is holding.  This reads calls out of capture *files* -
one, or two taken at the same time from opposite sides of the network - and turns each into the thing an engineer
actually reads when a call misbehaves: a ladder of every SIP message in order, the RTP that did or did not follow
it, and a short list of what is wrong with it.

Why two captures
----------------
A single capture answers "what did this end see".  Two, taken at the client and at the server, answer "what did the
network do to it in between", and that is a different and much harder question:

* **One-way audio.**  Signalling completes, both ends think the call is up, and the audio only goes one way.  With
  one capture you can see that you are sending and not receiving.  With two you can see *where* it stopped: the
  client sent RTP, the server never saw it.
* **Something rewrote the packets.**  Compare the same Call-ID's INVITE as it left the client against the one that
  arrived at the server: a Contact, a Via sent-by or an SDP connection line that differs between the two is proof
  that something on the path edited it - an ALG, an SBC, a firewall with SIP inspection.  No probe, active or
  passive, can establish that from one side; a two-sided capture establishes it by simple comparison.  That is what
  :data:`REWRITE_HEADERS` and the ``flow.rewritten`` finding are for.
* **A message that never arrived.**  An INVITE in the client capture with nothing matching in the server capture is
  a different fault from an INVITE the server rejected, and only two captures tell them apart.

Matching the two sides
----------------------
On **Call-ID**, not on the clock.  Call-ID is globally unique by RFC 3261 clause 8.1.1.4 and travels unchanged end
to end, while two capture PCs' clocks routinely differ by seconds and an NTP correction mid-capture can move one of
them underneath you.  So Call-ID is the join, and the clock offset between the captures is *derived* from the calls
that matched (:func:`estimate_skew`): the same message seen on both sides gives one sample of the offset, and the
median of those samples is the offset reported and used to line the ladder up.  The thing that would have broken
time-based matching becomes a measurement instead.

Two exceptions the code has to handle:

* A **B2BUA or SBC in the middle gives the two sides different Call-IDs** - and that is exactly the case where
  capturing both sides matters most.  When Call-ID fails, :func:`pair_across_sbc` looks for the same From and To
  user parts with overlapping lifetimes once the skew is taken out, and marks the pair ``matched_by`` ``"parties"``
  so the page can say the join is a guess rather than an identity.
* A call seen in **only one** capture is kept as itself, with the side it was seen on recorded.  It is not an error;
  it is often the finding.

Everything here is pure except :class:`FlowReader`, which reads capture files.  Nothing is written, nothing is sent,
and a file is only ever opened for reading.

Shapes (keys in this order)::

    SOURCE  = SOURCE_KEYS    # one loaded capture file
    LADDER  = LADDER_KEYS    # one row of a call's flow
    FLOWCALL= FLOWCALL_KEYS  # one call, merged across the sides it was seen on
    FINDING = FINDING_KEYS   # id, level, title, detail, advice, evidence - as tnt.proav writes them
    FLOW    = FLOW_KEYS      # the whole reading: sources, calls, skew, findings, counts
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import sipalg, sipcalls

log = logging.getLogger(__name__)

__all__ = ["SOURCE_KEYS", "LADDER_KEYS", "FLOWCALL_KEYS", "FINDING_KEYS", "SKEW_KEYS", "FLOW_KEYS", "STREAM_KEYS",
           "SLOTS", "FINDING_LEVELS", "FINDING_IDS", "REWRITE_HEADERS", "MAX_SOURCE_BYTES", "MAX_CALLS",
           "JITTER_WARN_MS", "JITTER_BAD_MS", "LOSS_WARN_PCT", "LOSS_BAD_PCT",
           "estimate_skew", "pair_across_sbc", "build_ladder", "call_findings", "FlowReader", "FlowError"]

SOURCE_KEYS = ("slot", "name", "path", "size", "packets", "sip_messages", "rtp_packets", "calls", "first_ts",
               "last_ts", "error")
LADDER_KEYS = ("index", "ts", "rel", "side", "src", "dst", "label", "kind", "method", "status", "reason",
               "cseq", "cseq_method", "has_sdp", "contact", "user_agent", "where", "note")
STREAM_KEYS = ("id", "side", "src", "sport", "dst", "dport", "codec", "packets", "lost", "loss_pct",
               "out_of_order", "jitter_ms", "duration_s", "decodable", "direction")
FLOWCALL_KEYS = ("id", "call_ids", "from_uri", "to_uri", "state", "status", "start_ts", "answer_ts", "end_ts",
                 "duration_s", "sides", "matched_by", "ladder", "streams", "findings", "note")
FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")
SKEW_KEYS = ("seconds", "samples", "matched_calls", "confident")
FLOW_KEYS = ("ts", "sources", "calls", "skew", "findings", "counts")
COUNTS_KEYS = ("sources", "calls", "matched", "one_sided", "messages", "streams")

#: The two capture slots.  "a" is whichever side the tech loaded first; the page names them.
SLOTS = ("a", "b")
FINDING_LEVELS = ("bad", "warn", "info", "good")
_LEVEL_ORDER = {level: index for index, level in enumerate(FINDING_LEVELS)}

#: Every finding this module can emit, so the UI and the mock can stay in step with it.
#: Most a single capture's inferred ALG tells will add to the findings list; past a couple they
#: are the same tell about the same rewrite, and a page of them reads as a page of faults.
MAX_TELLS = 4

FINDING_IDS: Tuple[str, ...] = (
    "flow.rewritten", "flow.missing", "flow.oneway", "flow.nomedia", "flow.noack", "flow.failed",
    "flow.cancelled", "flow.jitter", "flow.loss", "flow.short", "flow.ok", "flow.skew", "flow.onesided",
    # the single-capture ALG tells, borrowed whole from tnt.sipalg rather than restated here: one definition of
    # what an ALG looks like, wherever the evidence came from
    "alg.contact", "alg.sdp",
)

#: The headers a middlebox rewrites when it is "helping".  Comparing these between the two sides of one call is the
#: whole point of a two-sided capture: a difference is proof of rewriting, not an inference from it.
REWRITE_HEADERS = ("contact", "via_branch", "src", "dst")

MAX_SOURCE_BYTES = 512 * 1024 * 1024      # the largest capture file this reads
MAX_CALLS = 500                           # calls carried in one reading
MAX_LADDER = 400                          # rows of one call's ladder
JITTER_WARN_MS = 30.0                     # a phone's jitter buffer copes to about here
JITTER_BAD_MS = 80.0
LOSS_WARN_PCT = 1.0                       # G.711 without PLC is audibly rough past about 1 %
LOSS_BAD_PCT = 5.0
#: A call answered and torn down faster than this was probably not a conversation.
SHORT_CALL_S = 5.0
#: Skew samples needed before the measured offset is called confident.
MIN_SKEW_SAMPLES = 3


class FlowError(RuntimeError):
    """A capture could not be read; the message says why in words a person can act on."""


def _num(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _user_part(uri: Any) -> Optional[str]:
    """The user part of a SIP URI: ``sip:2001@pbx.example`` -> ``2001``.  Used only to pair calls across an SBC."""
    if not isinstance(uri, str) or not uri:
        return None
    body = uri.split(":", 1)[1] if ":" in uri else uri
    body = body.split(";", 1)[0].split(">", 1)[0]
    return body.split("@", 1)[0].strip() or None if "@" in body else None


def _label(message: Dict[str, Any]) -> str:
    """What a ladder row is called: ``INVITE``, ``180 Ringing``, ``200 OK (INVITE)``."""
    if message.get("kind") == "response":
        status, reason = message.get("status"), message.get("reason")
        head = f"{status} {reason}".strip() if reason else str(status)
        method = message.get("cseq_method")
        return f"{head} ({method})" if method else head
    return str(message.get("method") or "?")


def _message_key(message: Dict[str, Any]) -> Tuple[Any, ...]:
    """What makes one SIP message the *same* message on the other side of the network.

    Deliberately not the Via branch: a proxy adds its own, which is the point of the branch. Method, CSeq number and
    response status survive the trip, and together they identify a message inside one dialogue."""
    return (message.get("kind"), message.get("method"), message.get("cseq"), message.get("cseq_method"),
            message.get("status"))


# --------------------------------------------------------------------------- pairing the two sides
def estimate_skew(calls_a: Iterable[Dict[str, Any]], calls_b: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """How far capture B's clock runs behind A's, measured from the calls that appear in both.

    For every Call-ID in both captures, every message that appears on both sides gives one sample of
    ``ts_b - ts_a``; the median of those samples is the offset.  The median rather than the mean because one
    message delayed in the network is a real event and should not drag the estimate.  ``confident`` is False until
    :data:`MIN_SKEW_SAMPLES` samples agree, and the caller should say so rather than line two ladders up on a
    guess."""
    by_id_a = {call.get("call_id"): call for call in calls_a if call.get("call_id")}
    samples: List[float] = []
    matched = 0
    for call in calls_b:
        twin = by_id_a.get(call.get("call_id"))
        if twin is None:
            continue
        matched += 1
        seen: Dict[Tuple[Any, ...], float] = {}
        for message in twin.get("messages") or []:
            when = _num(message.get("ts"))
            if when is not None:
                seen.setdefault(_message_key(message), when)
        for message in call.get("messages") or []:
            when = _num(message.get("ts"))
            other = seen.get(_message_key(message))
            if when is not None and other is not None:
                samples.append(when - other)
    ordered = sorted(samples)
    middle = len(ordered) // 2
    offset = None
    if ordered:
        offset = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2.0
    return {"seconds": round(offset, 6) if offset is not None else None, "samples": len(ordered),
            "matched_calls": matched, "confident": len(ordered) >= MIN_SKEW_SAMPLES}


def pair_across_sbc(unmatched_a: List[Dict[str, Any]], unmatched_b: List[Dict[str, Any]],
                    skew: float = 0.0) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Pair calls the Call-ID could not, because a B2BUA or SBC gave each side its own.

    Matched on the From and To user parts with overlapping lifetimes once the skew is removed.  This is a guess and
    is labelled one: the caller marks the pair ``matched_by`` ``"parties"`` so the page never claims two legs are
    the same call when all that is known is that they look like it."""
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    taken: set = set()
    for left in unmatched_a:
        best: Optional[Dict[str, Any]] = None
        best_gap = None
        left_from, left_to = _user_part(left.get("from_uri")), _user_part(left.get("to_uri"))
        left_start, left_end = _num(left.get("start_ts")), _num(left.get("end_ts")) or _num(left.get("start_ts"))
        if left_from is None or left_start is None:
            continue
        for right in unmatched_b:
            if id(right) in taken:
                continue
            if _user_part(right.get("from_uri")) != left_from or _user_part(right.get("to_uri")) != left_to:
                continue
            right_start = _num(right.get("start_ts"))
            if right_start is None:
                continue
            gap = abs((right_start - skew) - left_start)
            right_end = _num(right.get("end_ts")) or right_start
            # the two legs have to overlap in time, allowing for the skew, or they are different calls that
            # happened to be between the same two parties
            if (right_start - skew) > (left_end or left_start) + SHORT_CALL_S:
                continue
            if left_start > (right_end - skew) + SHORT_CALL_S:
                continue
            if best_gap is None or gap < best_gap:
                best, best_gap = right, gap
        if best is not None:
            taken.add(id(best))
            out.append((left, best))
    return out


# --------------------------------------------------------------------------- the ladder
def build_ladder(sides: Dict[str, Dict[str, Any]], skew: float = 0.0) -> List[Dict[str, Any]]:
    """One call's messages from every side it was seen on, in the order they really happened.

    ``sides`` maps a slot to that side's CALL.  Side B's timestamps have the measured skew taken out so the two
    ladders interleave correctly; the row keeps the side it came from, so a row seen on only one side is visible as
    exactly that."""
    rows: List[Dict[str, Any]] = []
    for slot, call in sides.items():
        shift = skew if slot == "b" else 0.0
        for message in call.get("messages") or []:
            when = _num(message.get("ts"))
            if when is None:
                continue
            rows.append({
                "index": 0, "ts": round(when - shift, 6), "rel": 0.0, "side": slot,
                "src": message.get("src"), "dst": message.get("dst"), "label": _label(message),
                "kind": message.get("kind"), "method": message.get("method"), "status": message.get("status"),
                "reason": message.get("reason"), "cseq": message.get("cseq"),
                "cseq_method": message.get("cseq_method"), "has_sdp": bool(message.get("has_sdp")),
                "contact": message.get("contact"), "user_agent": message.get("user_agent"),
                "where": message.get("where"), "note": None,
            })
    rows.sort(key=lambda row: (row["ts"], row["side"]))
    del rows[MAX_LADDER:]
    first = rows[0]["ts"] if rows else 0.0
    for index, row in enumerate(rows):
        row["index"] = index
        row["rel"] = round(row["ts"] - first, 6)
    return rows


def _stream_rows(sides: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for slot, call in sides.items():
        for stream in call.get("streams") or []:
            packets = int(stream.get("packets") or 0)
            lost = int(stream.get("lost") or 0)
            total = packets + lost
            out.append({
                "id": stream.get("id"), "side": slot, "src": stream.get("src"), "sport": stream.get("sport"),
                "dst": stream.get("dst"), "dport": stream.get("dport"), "codec": stream.get("codec"),
                "packets": packets, "lost": lost,
                "loss_pct": round(lost / total * 100.0, 2) if total else None,
                "out_of_order": stream.get("out_of_order"), "jitter_ms": stream.get("jitter_ms"),
                "duration_s": stream.get("duration_s"), "decodable": bool(stream.get("decodable")),
                "direction": f"{stream.get('src')} -> {stream.get('dst')}",
            })
    return out


# --------------------------------------------------------------------------- what is wrong with it
def _finding(ident: str, level: str, title: str, detail: Optional[str] = None, advice: Optional[str] = None,
             evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


def _rewritten(sides: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Messages that are the same message on both sides but do not match: proof something edited them in flight."""
    if len(sides) < 2:
        return []
    left, right = sides.get("a") or {}, sides.get("b") or {}
    index: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for message in left.get("messages") or []:
        index.setdefault(_message_key(message), message)
    changes: List[Dict[str, Any]] = []
    for message in right.get("messages") or []:
        twin = index.get(_message_key(message))
        if twin is None:
            continue
        for field in REWRITE_HEADERS:
            before, after = twin.get(field), message.get(field)
            if before and after and before != after:
                changes.append({"message": _label(message), "field": field, "a": before, "b": after})
    return changes


def call_findings(sides: Dict[str, Dict[str, Any]], ladder: List[Dict[str, Any]],
                  streams: List[Dict[str, Any]], *, two_sided: bool) -> List[Dict[str, Any]]:
    """What is wrong with one call, worst first.  A check with nothing to go on is left out, never reported clean."""
    out: List[Dict[str, Any]] = []
    any_call = next(iter(sides.values()), {})
    state = any_call.get("state")
    status = any_call.get("status")

    changes = _rewritten(sides)
    if changes:
        fields = sorted({change["field"] for change in changes})
        out.append(_finding(
            "flow.rewritten", "bad", "Something on the path rewrote these packets",
            f"The same message does not match on the two sides of the network: {', '.join(fields)} differ between "
            "the client capture and the server capture. Nothing between two endpoints should be editing SIP.",
            "This is what a SIP ALG, an SBC or a firewall with SIP inspection does. If it is a router's SIP ALG, "
            "turn it off - it is the single most common cause of one-way audio and failed registrations.",
            changes[:12]))

    if two_sided:
        seen = {slot: {_message_key(m) for m in (call.get("messages") or [])} for slot, call in sides.items()}
        only_a = seen.get("a", set()) - seen.get("b", set())
        only_b = seen.get("b", set()) - seen.get("a", set())
        if only_a or only_b:
            rows = [{"side": row["side"], "message": row["label"], "at": row["rel"]} for row in ladder
                    if (_ladder_key(row) in only_a and row["side"] == "a")
                    or (_ladder_key(row) in only_b and row["side"] == "b")]
            out.append(_finding(
                "flow.missing", "bad" if only_a else "warn",
                f"{len(only_a) + len(only_b)} message(s) appear on only one side",
                "A message in one capture with nothing matching it in the other never made the trip - or was "
                "answered before it got there. This is the fault two captures exist to find.",
                "Look at where the ladder stops on the side that is missing it: that is the hop to investigate.",
                rows[:12]))

    sending = [s for s in streams if s["packets"]]
    if state in ("answered", "ended") and not sending:
        out.append(_finding(
            "flow.nomedia", "bad", "The call was answered but no audio was captured",
            "Signalling completed and both ends thought the call was up, but no RTP was seen at all.",
            "Check that the capture covered the media ports the SDP negotiated - and if it did, the audio never "
            "flowed. A firewall or NAT that passes signalling and drops media does exactly this."))
    elif sending:
        directions = {(s["src"], s["dst"]) for s in sending}
        reverse = {(dst, src) for src, dst in directions}
        if len(directions) == 1 or not (directions & reverse):
            out.append(_finding(
                "flow.oneway", "bad", "Audio only went one way",
                "RTP was captured in one direction and nothing came back the other way. Both ends believe the call "
                "is up; one of them hears silence.",
                "The usual causes, in order: a SIP ALG rewriting the SDP, symmetric NAT sending the return audio to "
                "a port that is not open, or a firewall passing signalling and dropping media.",
                [{"direction": s["direction"], "packets": s["packets"]} for s in sending[:6]]))

    if state == "answered" or any(row["status"] == 200 and row["cseq_method"] == "INVITE" for row in ladder):
        if not any(row["method"] == "ACK" for row in ladder):
            out.append(_finding(
                "flow.noack", "warn", "The 200 OK was never acknowledged",
                "The call was answered but no ACK followed. The answering end will keep re-sending the 200 OK and "
                "then tear the call down.",
                "An ACK that goes missing is usually addressed somewhere the network cannot deliver - look at the "
                "Contact in the 200 OK."))

    # A refusal of an INVITE that a newer INVITE (a higher CSeq, same Call-ID) then replaced was a step, not the
    # end: RFC 3261 22.2 answers a 401 or 407 by sending the INVITE again with credentials, which is how nearly every
    # call through an authenticating PBX or trunk starts. Only a refusal nothing replaced is the call's failure.
    failure = next((row for row in ladder if isinstance(row["status"], int) and row["status"] >= 400
                    and not _superseded(row, ladder)), None)
    if failure is not None:
        challenged = failure["status"] in (401, 407) and failure.get("cseq_method") == "INVITE"
        out.append(_finding(
            "flow.failed", "warn" if state == "cancelled" else "bad",
            (f"The call failed at the credential challenge: {failure['label']}" if challenged
             else f"The call failed: {failure['label']}"),
            f"The far end answered with {failure['label']}"
            + (f" at {failure['rel']} s into the flow." if failure.get("rel") is not None else "."),
            _failure_advice(failure["status"]),
            {"status": failure["status"], "reason": failure["reason"]}))
    if state == "cancelled":
        out.append(_finding(
            "flow.cancelled", "info", "The caller hung up before it was answered",
            "A CANCEL was sent while the call was still ringing.", None))

    for stream in streams:
        jitter, loss = stream.get("jitter_ms"), stream.get("loss_pct")
        if isinstance(jitter, (int, float)) and jitter >= JITTER_WARN_MS:
            out.append(_finding(
                "flow.jitter", "bad" if jitter >= JITTER_BAD_MS else "warn",
                f"Audio arrived unevenly ({jitter} ms of jitter)",
                f"{stream['direction']} varied by {jitter} ms between packets. A phone's jitter buffer absorbs "
                "some of this; past a few tens of milliseconds it cannot, and the audio breaks up.",
                "Jitter this size is congestion or a queue, not the phone. Check QoS along the path and whether "
                "the link is saturated while calls are up.",
                {"stream": stream["direction"], "jitter_ms": jitter}))
        if isinstance(loss, (int, float)) and loss >= LOSS_WARN_PCT:
            out.append(_finding(
                "flow.loss", "bad" if loss >= LOSS_BAD_PCT else "warn",
                f"Audio packets were lost ({loss} %)",
                f"{stream['direction']} lost {stream['lost']} of {stream['packets'] + stream['lost']} packets.",
                "G.711 has no error correction: every lost packet is a gap you can hear. Look for a saturated "
                "link, a duplex mismatch or Wi-Fi in the path.",
                {"stream": stream["direction"], "loss_pct": loss, "lost": stream["lost"]}))

    duration = _num(any_call.get("duration_s"))
    if state == "ended" and duration is not None and 0 < duration < SHORT_CALL_S:
        out.append(_finding(
            "flow.short", "info", f"The call lasted {round(duration, 1)} s",
            "Answered and torn down again almost immediately. That is often someone hanging up on silence - worth "
            "reading with the audio findings above.", None))

    if not out and state in ("answered", "ended"):
        # A stream with no jitter figure (a dynamic codec whose SDP was not captured, so its clock rate is unknown)
        # was not checked for jitter, and "clean" would claim a check that never ran.
        unmeasured = [s for s in sending if s["packets"] > 1 and not isinstance(s.get("jitter_ms"), (int, float))]
        if not sending:
            detail = "Signalling completed cleanly."
        elif unmeasured:
            where = ("" if len(unmeasured) == len(sending)
                     else f" on {len(unmeasured)} of the {len(sending)} streams")
            detail = (f"Signalling completed and audio flowed both ways, but jitter was not measured{where}: the "
                      "SDP that gives the codec's clock rate was not in the capture, so how evenly the audio "
                      "arrived is not known.")
        else:
            detail = "Signalling completed, audio flowed both ways, and the streams were clean."
        out.append(_finding("flow.ok", "good", "Nothing wrong with this call", detail, None))
    out.sort(key=lambda finding: _LEVEL_ORDER.get(finding["level"], 9))
    return out


def _ladder_key(row: Dict[str, Any]) -> Tuple[Any, ...]:
    return (row.get("kind"), row.get("method"), row.get("cseq"), row.get("cseq_method"), row.get("status"))


def _host(endpoint: Any) -> Any:
    """The address part of a message's ``ip:port`` (``[v6]:port`` for IPv6); anything else unchanged."""
    if not isinstance(endpoint, str):
        return endpoint
    if endpoint.startswith("["):
        return endpoint[1:endpoint.find("]")] if "]" in endpoint else endpoint
    return endpoint.rsplit(":", 1)[0] if endpoint.count(":") == 1 else endpoint


def _superseded(row: Dict[str, Any], ladder: List[Dict[str, Any]]) -> bool:
    """True when *row* answers an INVITE that the same sender, in the same capture, then sent again with a higher CSeq.

    CSeq numbers only compare within one sender's requests on one Call-ID (RFC 3261 8.1.1.5). Two captures either
    side of an SBC are two Call-IDs, each numbered from wherever its own sender began, and in one dialog the callee's
    re-INVITE counts from its own start too. So a response is compared only with INVITEs from the end it was sent to
    (the INVITE's sender), on its own side; the port is left out because a response need not go back to the port the
    request came from. When no INVITE on that side came from there (a capture that saw only the answers), the side's
    own INVITEs are the best evidence there is."""
    cseq = row.get("cseq")
    if row.get("cseq_method") != "INVITE" or not isinstance(cseq, int) or isinstance(cseq, bool):
        return False
    side, sender = row.get("side"), _host(row.get("dst"))
    same_side = [other for other in ladder if other.get("side") == side and other.get("kind") == "request"
                 and other.get("method") == "INVITE" and isinstance(other.get("cseq"), int)]
    same_sender = [other for other in same_side if _host(other.get("src")) == sender]
    return any(other["cseq"] > cseq for other in (same_sender or same_side))


def _failure_advice(status: Any) -> Optional[str]:
    if not isinstance(status, int):
        return None
    if status in (401, 407):
        return "That is an authentication challenge that was never passed: the far end asked for credentials, "\
               "and either the caller never sent the request again with them or the ones it sent were refused. "\
               "Check the account's user name, authentication ID and password on the phone or trunk."
    if status == 403:
        return "The far end refused the call outright. Check the account, the caller ID it presented and whether "\
               "the source address is permitted on the trunk."
    if status == 404:
        return "The number was not recognised by the far end. Check the dial plan and how the digits were sent."
    if status == 408:
        return "Nothing answered in time. If the INVITE also appears in a capture of the far side, the reply is "\
               "what went missing; if it does not, the INVITE never arrived."
    if status == 480 or status == 486:
        return "The far end was reachable but unavailable or busy - usually a phone, not the network."
    if status == 488:
        return "The two ends could not agree on a codec. Compare the SDP in the INVITE with the one in this reply."
    if 500 <= status < 600:
        return "The far end reported its own failure. This is generally the provider's side to investigate."
    return None


# --------------------------------------------------------------------------- reading the files
class _Source:
    """One loaded capture: its own CallTracker, and where in the file each SIP message came from."""

    __slots__ = ("slot", "path", "name", "size", "tracker", "packets", "offsets", "linktype", "first_ts",
                 "last_ts", "error")

    def __init__(self, slot: str, path: str, name: str, size: int) -> None:
        self.slot, self.path, self.name, self.size = slot, path, name, size
        self.tracker = sipcalls.CallTracker(max_calls=MAX_CALLS, max_messages=MAX_LADDER)
        self.packets = 0
        #: packet number -> the byte offset of its block, so a header view is one seek rather than a second walk
        self.offsets: Dict[int, int] = {}
        self.linktype = 1
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.error: Optional[str] = None

    def view(self) -> Dict[str, Any]:
        stats = self.tracker.stats()
        return {"slot": self.slot, "name": self.name, "path": self.path, "size": self.size,
                "packets": self.packets, "sip_messages": stats.get("sip_messages", 0),
                "rtp_packets": stats.get("rtp_packets", 0), "calls": stats.get("calls", 0),
                "first_ts": self.first_ts, "last_ts": self.last_ts, "error": self.error}


class FlowReader:
    """One or two capture files read for their SIP calls, and the merged view of them.

    Separate from :class:`tnt.capture.CaptureManager` on purpose.  That holds exactly one session, tears it down to
    open a file and refuses to open one at all while a live capture runs - all correct for a page whose job is the
    live capture, and all wrong for a page whose job is to hold two files side by side and compare them.  This
    opens files read-only, keeps its own trackers, and never touches the capture page's session.

    Module-level seams tests monkeypatch: ``_iter_packets``, ``_read_packet_at`` and ``_summarize``."""

    def __init__(self, *, max_bytes: int = MAX_SOURCE_BYTES) -> None:
        self._max_bytes = int(max_bytes)
        self._sources: Dict[str, _Source] = {}

    # -- loading ---------------------------------------------------------------------------------
    def open(self, path: Any, slot: str = "a") -> Dict[str, Any]:
        """Read a capture file into *slot* (``"a"`` or ``"b"``), replacing whatever was there."""
        if slot not in SLOTS:
            raise ValueError(f"a capture goes in slot {' or '.join(SLOTS)}, not {slot!r}")
        text = str(path or "").strip()
        if not text:
            raise ValueError("give the full path of a capture file")
        if not os.path.isabs(text):
            raise ValueError("give the full path of a capture file, not a relative one")
        try:
            info = os.stat(text)
        except OSError as exc:
            raise FlowError(f"that capture could not be opened ({exc.strerror or 'no such file'})") from exc
        if not os.path.isfile(text):
            raise FlowError("that path is not a file")
        if info.st_size > self._max_bytes:
            raise FlowError(f"that capture is larger than {self._max_bytes // (1024 * 1024)} MB")
        source = _Source(slot, text, os.path.basename(text), int(info.st_size))
        self._read_into(source)
        self._sources[slot] = source
        log.info("SIP flow: read %s (%d packets, %d call(s)) into slot %s",
                 source.name, source.packets, source.tracker.stats().get("calls", 0), slot)
        return source.view()

    def _read_into(self, source: "_Source") -> None:
        """Walk the file once: every SIP and RTP packet into the tracker, every SIP packet's offset remembered."""
        try:
            with open(source.path, "rb") as handle:
                for offset, packet in _iter_packets(handle):
                    source.packets += 1
                    when = packet.get("ts")
                    if isinstance(when, (int, float)):
                        source.first_ts = when if source.first_ts is None else min(source.first_ts, when)
                        source.last_ts = when if source.last_ts is None else max(source.last_ts, when)
                    if packet.get("linktype"):
                        source.linktype = int(packet["linktype"])
                    self._feed(source, packet, offset, source.packets)
        except FlowError:
            raise
        except Exception as exc:                 # noqa: BLE001 - a half-read capture still shows what it had
            source.error = str(exc) or "the capture could not be read to the end"
            log.debug("reading %s stopped early", source.name, exc_info=True)

    def _feed(self, source: "_Source", packet: Dict[str, Any], offset: int, number: int) -> None:
        data = packet.get("data")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return
        try:
            summary = _summarize(bytes(data))
        except Exception:                        # noqa: BLE001 - one unreadable frame never stops the walk
            return
        layers = tuple(summary.get("layers") or ())
        payload = summary.get("payload")
        if payload is None or ("SIP" not in layers and "RTP" not in layers):
            return
        when = packet.get("ts")
        when = float(when) if isinstance(when, (int, float)) else 0.0
        src, dst = str(summary.get("src") or ""), str(summary.get("dst") or "")
        sport, dport = int(summary.get("sport") or 0), int(summary.get("dport") or 0)
        try:
            if "SIP" in layers:
                message = sipcalls.parse_sip(payload)
                if message is not None:
                    source.offsets[number] = offset
                    source.tracker.add_sip(message, when, src, sport, dst, dport, where=number, side=source.slot)
            else:
                rtp = sipcalls.parse_rtp(payload)
                if rtp is not None:
                    source.tracker.add_rtp(rtp, when, src, sport, dst, dport)
        except Exception:                        # noqa: BLE001
            log.debug("a packet of %s could not be tracked", source.name, exc_info=True)

    def close(self, slot: str) -> None:
        self._sources.pop(slot, None)

    def clear(self) -> None:
        self._sources.clear()

    def sources(self) -> List[Dict[str, Any]]:
        return [self._sources[slot].view() for slot in SLOTS if slot in self._sources]

    # -- the merged reading ----------------------------------------------------------------------
    def _merge(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Every call, each as the sides it was seen on, plus the measured clock offset between the captures."""
        calls_a = self._sources["a"].tracker.calls() if "a" in self._sources else []
        calls_b = self._sources["b"].tracker.calls() if "b" in self._sources else []
        skew = estimate_skew(calls_a, calls_b)
        offset = skew["seconds"] or 0.0
        by_id_b = {call.get("call_id"): call for call in calls_b if call.get("call_id")}
        groups: List[Dict[str, Any]] = []
        paired_b: set = set()
        for call in calls_a:
            twin = by_id_b.get(call.get("call_id"))
            if twin is not None:
                paired_b.add(id(twin))
                groups.append({"sides": {"a": call, "b": twin}, "matched_by": "call-id"})
            else:
                groups.append({"sides": {"a": call}, "matched_by": None})
        leftovers_b = [call for call in calls_b if id(call) not in paired_b]
        # a B2BUA or SBC gives each side its own Call-ID, which is exactly when two captures matter most
        one_sided_a = [group for group in groups if set(group["sides"]) == {"a"}]
        for left, right in pair_across_sbc([g["sides"]["a"] for g in one_sided_a], leftovers_b, offset):
            for group in one_sided_a:
                if group["sides"]["a"] is left:
                    group["sides"]["b"] = right
                    group["matched_by"] = "parties"
                    paired_b.add(id(right))
                    break
        for call in leftovers_b:
            if id(call) not in paired_b:
                groups.append({"sides": {"b": call}, "matched_by": None})
        return groups, skew

    def view(self, *, clock: Any = None) -> Dict[str, Any]:
        """The whole reading: the sources, every call merged across the sides it was on, and the findings."""
        groups, skew = self._merge()
        two_sided = len(self._sources) > 1
        offset = skew["seconds"] or 0.0
        calls: List[Dict[str, Any]] = []
        for group in groups:
            calls.append(self._flow_call(group, offset, two_sided))
        calls.sort(key=lambda call: (call["start_ts"] if call["start_ts"] is not None else 0.0))
        matched = sum(1 for call in calls if len(call["sides"]) > 1)
        findings = self._flow_findings(calls, skew, two_sided)
        now = float(clock()) if callable(clock) else None
        return {
            "ts": now,
            "sources": self.sources(),
            "calls": calls,
            "skew": skew,
            "findings": findings,
            "counts": {"sources": len(self._sources), "calls": len(calls), "matched": matched,
                       "one_sided": len(calls) - matched,
                       "messages": sum(len(call["ladder"]) for call in calls),
                       "streams": sum(len(call["streams"]) for call in calls)},
        }

    def _flow_call(self, group: Dict[str, Any], offset: float, two_sided: bool) -> Dict[str, Any]:
        sides = group["sides"]
        primary = sides.get("a") or sides.get("b") or {}
        ladder = build_ladder(sides, offset)
        streams = _stream_rows(sides)
        findings = call_findings(sides, ladder, streams, two_sided=two_sided and len(sides) > 1)
        starts = [_num(call.get("start_ts")) for call in sides.values()]
        starts = [value for value in starts if value is not None]
        return {
            "id": primary.get("id"),
            "call_ids": sorted({call.get("call_id") for call in sides.values() if call.get("call_id")}),
            "from_uri": primary.get("from_uri"), "to_uri": primary.get("to_uri"),
            "state": primary.get("state"), "status": primary.get("status"),
            "start_ts": min(starts) if starts else None,
            "answer_ts": primary.get("answer_ts"), "end_ts": primary.get("end_ts"),
            "duration_s": primary.get("duration_s"),
            "sides": sorted(sides), "matched_by": group.get("matched_by"),
            "ladder": ladder, "streams": streams, "findings": findings, "note": primary.get("note"),
        }

    def _flow_findings(self, calls: List[Dict[str, Any]], skew: Dict[str, Any],
                       two_sided: bool) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if two_sided:
            seconds, samples = skew["seconds"], skew["samples"]
            if seconds is None:
                out.append(_finding(
                    "flow.skew", "warn", "The two captures could not be lined up",
                    "No call appears in both captures, so there is nothing to measure the clock difference from "
                    "and the two ladders are drawn on their own clocks.",
                    "Check the captures overlap in time and were taken of the same traffic. If a B2BUA or SBC sits "
                    "between the two points, each side has its own Call-ID and calls are paired by their parties "
                    "instead - which needs the From and To to survive the hop."))
            else:
                out.append(_finding(
                    "flow.skew", "info" if skew["confident"] else "warn",
                    f"The two capture clocks differ by {abs(round(seconds, 3))} s",
                    f"Measured from {samples} message(s) seen in both captures across {skew['matched_calls']} "
                    f"call(s). Capture B runs {'behind' if seconds < 0 else 'ahead of'} capture A, and the merged "
                    "ladder has that taken out."
                    + ("" if skew["confident"] else " Only a few samples, so treat the alignment as approximate."),
                    None, {"seconds": seconds, "samples": samples}))
            one_sided = [call for call in calls if len(call["sides"]) == 1]
            if one_sided:
                out.append(_finding(
                    "flow.onesided", "info",
                    f"{len(one_sided)} call(s) appear in only one capture",
                    "Not necessarily wrong - the two captures rarely start and stop together, and a call outside "
                    "the overlap is simply outside it. It is only a fault if the call should have crossed the "
                    "point the other capture was taken at.",
                    None,
                    [{"id": call["id"], "from": call["from_uri"], "side": call["sides"][0]}
                     for call in one_sided[:10]]))
        out.extend(self._passive_tells())
        out.sort(key=lambda finding: _LEVEL_ORDER.get(finding["level"], 9))
        return out

    def _passive_tells(self) -> List[Dict[str, Any]]:
        """The marks an ALG leaves that a single capture can show (:func:`tnt.sipalg.passive_tells`).

        Read off each source's own tracker rather than off the merged ladder: a tracker message keeps ``sdp_c``,
        the address the sender told the far end to send audio to, and the ladder does not.  A two-sided capture
        proves rewriting outright (``flow.rewritten``) and needs no inference at all, so these are only offered
        where that proof is not available - which, for most techs most of the time, is every capture they have."""
        if len(self._sources) > 1:
            return []
        out: List[Dict[str, Any]] = []
        for source in self._sources.values():
            try:
                tells = sipalg.passive_tells(source.tracker.calls())
            except Exception:               # noqa: BLE001 - a tell is a bonus; the flow stands without it
                log.debug("the passive ALG tells could not be read from %s", source.name, exc_info=True)
                continue
            for tell in tells:
                out.append(_finding(
                    tell["id"], "warn",
                    "A SIP ALG may be rewriting this call" if tell["id"] == "alg.contact"
                    else "The audio address in the SDP is not the sender's",
                    str(tell.get("detail") or ""),
                    "This is one capture's inference, not proof. The SIP ALG check on this page probes your own "
                    "server and says outright whether something rewrote what TNT sent; a capture from both sides "
                    "of the network settles it beyond doubt.",
                    tell.get("evidence")))
        return out[:MAX_TELLS]

    # -- one call's detail -----------------------------------------------------------------------
    def call(self, call_id: Any) -> Optional[Dict[str, Any]]:
        wanted = str(call_id or "")
        for call in self.view()["calls"]:
            if call["id"] == wanted or wanted in (call["call_ids"] or []):
                return call
        return None

    def headers(self, side: Any, number: Any) -> Optional[Dict[str, Any]]:
        """Every header of the SIP packet a ladder row points at, read back from the file on demand.

        The ladder carries the packet's number, not its text: a few bytes a message instead of a few kilobytes, and
        the bytes on disk are what a header view wants anyway.  The offset remembered while loading turns this into
        one seek; a file that has changed underneath falls back to walking it again rather than showing the wrong
        packet."""
        source = self._sources.get(str(side or ""))
        if source is None:
            return None
        try:
            wanted = int(number)
        except (TypeError, ValueError):
            return None
        data = self._packet_bytes(source, wanted)
        if data is None:
            return None
        summary = _summarize(data)
        payload = summary.get("payload")
        if payload is None:
            return None
        view = sipcalls.sip_headers(payload)
        if view is None:
            return None
        view = dict(view)
        view["packet"] = wanted
        view["side"] = source.slot
        view["source"] = source.name
        return view

    def _packet_bytes(self, source: "_Source", number: int) -> Optional[bytes]:
        offset = source.offsets.get(number)
        if offset is not None:
            packet = _read_packet_at(source.path, offset, linktype=source.linktype)
            data = (packet or {}).get("data")
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
        try:                                      # the index missed: walk the file rather than show a wrong packet
            with open(source.path, "rb") as handle:
                for index, packet in enumerate(_iter_packets_plain(handle), start=1):
                    if index == number:
                        data = packet.get("data")
                        return bytes(data) if isinstance(data, (bytes, bytearray)) else None
        except Exception:                         # noqa: BLE001
            log.debug("packet %d of %s could not be re-read", number, source.name, exc_info=True)
        return None

    def audio(self, call_id: Any, *, side: Optional[str] = None, max_seconds: float = 600.0) -> Optional[bytes]:
        """One call's audio as a WAV, from whichever side was asked for (the first side that has any by default)."""
        wanted = str(call_id or "")
        for slot in ([side] if side in SLOTS else list(SLOTS)):
            source = self._sources.get(slot or "")
            if source is None:
                continue
            for call in source.tracker.calls():
                if call.get("id") == wanted or call.get("call_id") == wanted:
                    audio = source.tracker.call_audio(call.get("call_id") or wanted, max_seconds=max_seconds)
                    if audio:
                        return audio
        return None

    def stream_audio(self, stream_id: Any, *, max_seconds: float = 600.0) -> Optional[bytes]:
        """One RTP direction on its own - which is how a one-way-audio call is actually confirmed by ear."""
        wanted = str(stream_id or "")
        for slot in SLOTS:
            source = self._sources.get(slot)
            if source is None:
                continue
            audio = source.tracker.audio(wanted, max_seconds=max_seconds)
            if audio:
                return audio
        return None


# --------------------------------------------------------------------------- seams
def _iter_packets(handle: Any) -> Iterable[Tuple[int, Dict[str, Any]]]:
    from . import pcapng
    return pcapng.iter_packets_with_offsets(handle)


def _iter_packets_plain(handle: Any) -> Iterable[Dict[str, Any]]:
    from . import pcapng
    return pcapng.iter_packets(handle)


def _read_packet_at(path: str, offset: int, *, linktype: int = 1) -> Optional[Dict[str, Any]]:
    from . import pcapng
    try:
        return pcapng.read_packet_at(path, offset, linktype=linktype)
    except Exception:                             # noqa: BLE001
        return None


def _summarize(frame: bytes) -> Dict[str, Any]:
    from . import dissect
    return dissect.summarize(frame)
