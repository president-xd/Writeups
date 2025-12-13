let table = null;

class Table {
  constructor() {
    // BEGIN setup ui
    this.parchmentEl = document.querySelector("img#parchment");
    this.parchmentRect = this.parchmentEl.getBoundingClientRect();
    this.svgEl = SVG()
      .addTo("#table")
      .size(this.parchmentRect.width, this.parchmentRect.height);
    this.tableBar = document.getElementById("table-bar");
    this.tableText = document.getElementById("table-text");
    this.svgPaper = this.svgEl
      .rect(400, 400)
      .attr({
        class: "svgPaper",
      })
      .fill("transparent");
    // END setup ui

    this.strokes = [];
    this.polylines = [];
    this.isDown = false;

    // BEGIN handle document events
    document.body.addEventListener("keydown", (ev) => {
      switch (ev.key) {
        case "Backspace":
          this.strokes.pop();
          this.polylines.pop().remove();
          this.etch();
          break;
        case "Escape":
          this.strokes = [];
          this.polylines.forEach((p) => p.remove());
          this.polylines = [];
          this.etch();
          break;
        // deep etch
        case "Enter":
          this.etch(true);
          break;
        default:
          break;
      }
    });
    // END

    // BEGIN setup paper event handlers
    this.svgPaper.on("mousedown", (ev) => {
      this.isDown = true;
      this.strokes.push([ev.offsetX, ev.offsetY]);
      let polyline = this.svgEl
        .polyline(this.strokes[this.strokes.length - 1])
        .fill("transparent")
        .stroke({
          color: "var(--crimson)",
          opacity: 0.5,
          width: "3pt",
          linecap: "round",
        });

      this.polylines.push(polyline);
    });

    this.svgPaper.on(
      "mousemove",
      throttle((ev) => {
        if (this.isDown) {
          let currentStroke = this.strokes[this.strokes.length - 1];
          currentStroke.push(ev.offsetX, ev.offsetY);

          this.polylines[this.strokes.length - 1].plot(currentStroke);
        }
      }, 20)
    );

    this.svgPaper.on(["mouseup", "mouseleave"], (ev) => {
      if (this.isDown) {
        this.etch();
        this.isDown = false;

        let currentStroke = this.strokes[this.strokes.length - 1];
        if (this.polylines.length) {
          this.polylines[this.strokes.length - 1]
            .animate(1000)
            .plot(currentStroke.map((xy, i) => (i % 2 ? xy + 5 : xy)))
            .stroke({ opacity: 1 });
        }
      }
    });
    // END setup paper event handlers

    // BEGIN setup websocket handlers
    this.ws = new WebSocket(`ws://${window.location.host}`);

    this.ws.addEventListener("open", (ev) => {
      console.log("[+] Connected to WebSocket");
    });

    this.ws.addEventListener("message", (ev) => {
      try {
        let data = JSON.parse(ev.data);

        switch (data.type) {
          case "ocr":
            this.tableText.innerText = data.text;
            break;
          case "ocr-write":
            this.tableText.innerText = data.text;
            console.log(`[+] Successfully double etched into ${data.filename}`);
            break;
          default:
            console.error(data);
            break;
        }
      } catch (err) {
        console.err(err);
        console.log(ev.data);
      }
    });
    // END setup websocket handlers
  }

  adjustParchment() {
    this.parchmentRect = this.parchmentEl.getBoundingClientRect();
    this.svgEl.size(this.parchmentRect.width, this.parchmentRect.height);
    this.svgPaper.x(0.235 * this.parchmentRect.width);
    this.svgPaper.y(0.145 * this.parchmentRect.height);
    this.tableBar.style.left = this.svgPaper.x() + "px";
    this.tableBar.style.top = this.svgPaper.y() + "px";
    this.svgPaper.width("53%");
    this.svgPaper.height("77%");
  }

  etch(deep = false) {
    this.ws.send(
      JSON.stringify({
        type: (deep ? "deep-" : "") + "etch",
        x: this.svgPaper.x(),
        y: this.svgPaper.y(),
        width: this.svgPaper.node.getBBox().width,
        height: this.svgPaper.node.getBBox().height,
        points: this.polylines.map((p) => p.node.attributes.points.value),
      })
    );
  }
}

window.addEventListener("load", () => {
  table = new Table();
  table.adjustParchment();

  const quill = document.getElementById("quill");

  document.body.addEventListener("mousemove", (e) => {
    quill.style.left = e.clientX + "px";
    quill.style.top = e.clientY + "px";
  });
});

window.addEventListener("resize", () => {
  table.adjustParchment();
});

function debounce(callback, wait) {
  var timeout;
  return function (e) {
    clearTimeout(timeout);
    timeout = setTimeout(() => callback(e), wait);
  };
}

function throttle(callback, wait) {
  var timeout;
  return function (e) {
    if (timeout) return;
    timeout = setTimeout(() => (callback(e), (timeout = undefined)), wait);
  };
}
