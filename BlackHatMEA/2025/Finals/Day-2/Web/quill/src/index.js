const process = require("node:process");
const cp = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const ejs = require("ejs");
const { WebSocketServer } = require("ws");
const { Resvg } = require("@resvg/resvg-js");
const tesseract = require("tesseract.js");

const PORT = process.env.PORT || 3000;

const app = express();

// BEGIN setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const textDir = path.join(__dirname, "static", "text");
const uploadsDir = path.join(__dirname, "uploads");

// constant clean up
setInterval(async () => {
  let textFiles = await fs.promises.readdir(textDir);
  console.log(`[*] Cleaning up ${textFiles.length} files`);
  for (let file of textFiles) {
    await fs.promises.unlink(path.join(textDir, file));
  }
}, 1 * 60 * 1000);

Array(textDir, uploadsDir).forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
});

app.use(express.static(path.join(__dirname, "static")));
app.use(
  session({
    resave: false,
    saveUninitialized: false,
    secret: Math.random().toString(16),
  })
);
// END setup

app.get("/", (req, res) => {
  return res.render("index");
});

const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const rip = req.socket.remoteAddress;
  const rport = req.socket.remotePort;
  console.log(`[${wss.clients.size}] Connection from ${rip}:${rport}!`);

  ws.on("error", console.error);

  ws.on("message", async (message) => {
    try {
      const data = JSON.parse(message);

      let text;
      switch (data.type) {
        case "etch":
          text = await handleEtch(data);
          ws.send(JSON.stringify({ type: "ocr", text }));
          break;

        case "deep-etch":
          text = await handleEtch(data);
          filename = Math.random().toString(32).substring(2) + ".txt";
          filepath = path.join(textDir, filename);

          command = `echo "${text.replace(/['" \n]/g, "")}" | tee ${filepath}`;
          console.log("[*] Executing", command);

          cp.exec(command, { encoding: "ascii" }, (err, stdout, stderr) => {
            if (!err && !stderr) {
              ws.send(JSON.stringify({ type: "ocr-write", text, filename }));
              return;
            }
            ws.send(JSON.stringify({ error: error + " | " + stderr }));
            console.log("Error:", err);
            console.log("stderr:", stderr);
          });

          break;
        default:
          console.log("[!] Unknown message type");
          ws.send(JSON.stringify({ error: "Unknown message type" }));
          break;
      }
    } catch (err) {
      console.error(err);
      ws.close();
    }
  });
});

const pointsToImage = async (x, y, width, height, points) => {
  let svg = await ejs.renderFile(path.join(__dirname, "views", "svg.ejs"), {
    x,
    y,
    width,
    height,
    points,
  });

  let filename = Math.random().toString(16).substring(2) + ".svg";

  await fs.promises.writeFile(path.join(uploadsDir, filename), svg);

  const resvg = new Resvg(svg);
  const pngData = resvg.render();
  const pngBuffer = pngData.asPng();

  await fs.promises.writeFile(path.join(uploadsDir, filename), pngBuffer);

  return filename;
};

const imageToText = async (imagePath) => {
  const ocrWorker = await tesseract.createWorker("eng");

  const {
    data: { text },
  } = await ocrWorker.recognize(path.join(uploadsDir, imagePath));
  console.log("ocr:", text);

  await fs.promises.unlink(path.join(uploadsDir, imagePath));
  await ocrWorker.terminate();
  return text;
};

const handleEtch = async (data) => {
  let { x, y, width, height, points } = data;

  let start = performance.now();
  let imagePath = await pointsToImage(x, y, width, height, points);
  console.log(`[svg2img] took ${(performance.now() - start).toFixed(2)}ms`);
  start = performance.now();
  let text = await imageToText(imagePath);
  console.log(`[img2txt] took ${(performance.now() - start).toFixed(2)}ms`);

  return text;
};

const server = app.listen(PORT, (err) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`App listening on ${PORT}`);
});

server.on("upgrade", (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});
