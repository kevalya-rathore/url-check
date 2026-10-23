# api.py - a tiny local server so the browser extension can show its results on the web page itself.
# Run it next to the app with:  python api.py
# It listens on 127.0.0.1 only, so nothing outside this computer can reach it, and it never opens any link.
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from logic import analyze_page_links

PORT = 8600


class CheckLinks(BaseHTTPRequestHandler):
    def do_POST(self):
        """POST /check with [{"h": link, "t": its text}, ...] -> [{"href", "level", "score", "reasons"}, ...]"""
        if self.path != "/check":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            links = list(json.loads(self.rfile.read(length)))
        except (ValueError, TypeError):
            self.send_error(400, "Expected a JSON list of links")
            return

        answer = []
        for result in analyze_page_links(links, limit=300):
            answer.append({
                "href": result["href"],
                "level": result["level"],
                "score": result["score"],
                "reasons": [signal["title"] for signal in result["signals"] if signal["points"] > 0],
            })

        body = json.dumps(answer).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"Aegis Guard link checker for the extension: http://127.0.0.1:{PORT}/check  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", PORT), CheckLinks).serve_forever()
