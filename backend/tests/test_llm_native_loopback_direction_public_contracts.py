"""Reference enrichment uses its real HTTP transport with an owned local peer."""

import json
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Queue
from threading import Thread

from app.services import brain
from app.services.llm import LLMAnalyzer
from app.services.patterns import JournalEntry


def test_public_enrichment_preserves_native_finding_direction_over_real_loopback_http():
    today = date(2026, 10, 5)
    start = today - timedelta(days=83)
    entries = []
    for index in range(84):
        day = start + timedelta(days=index)
        if day == today - timedelta(days=4):
            mood = -0.9
        elif day >= today - timedelta(days=13):
            mood = -0.2
        else:
            mood = 0.05 if index % 2 else -0.05
        entries.append(JournalEntry("ordinary recent mood notes", day, sentiment=mood))
    first = brain.update(brain.fresh_state(), entries, today)
    entries += [
        JournalEntry("ordinary recent mood notes", today + timedelta(days=offset), sentiment=-0.2)
        for offset in range(1, 8)
    ]
    result = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), entries, today + timedelta(days=7)
    )
    (finding,) = [card for card in result.surfaced if card.kind == "mood_shift"]
    assert finding.detail["direction"] == "lower"

    received = Queue()
    narrative = "A quieter mood appears in these recent notes."

    class OwnedPeer(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.put((self.path, payload))
            # Fixed protocol response from an owned local peer. This tests
            # reference extraction and native HTTP, not model inference.
            content = json.dumps(
                {
                    "patterns": [
                        {
                            "kind": finding.kind,
                            "label": finding.label,
                            "narrative": narrative,
                        }
                    ],
                }
            )
            response = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedPeer)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        analyzer = LLMAnalyzer(
            f"http://127.0.0.1:{server.server_address[1]}", "owned-local-test-key", "reference-test"
        )
        refined = analyzer.extract_patterns(entries, findings=[finding])
        assert len(refined) == 1
        (returned,) = refined
        assert (returned.kind, returned.label) == (finding.kind, finding.label)
        assert returned.occurrences == finding.occurrences
        assert returned.detail == {**finding.detail, "narrative": narrative}
        path, payload = received.get(timeout=2)
        assert path == "/chat/completions"
        sent = json.loads(payload["messages"][1]["content"])
        assert sent["findings"] == [
            {
                "kind": finding.kind,
                "label": finding.label,
                "direction": finding.detail["direction"],
            }
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
