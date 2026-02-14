const crypto = require("crypto");
const express = require("express");

const {
  IG_USER_ID,
  PAGE_ID,
  PAGE_ACCESS_TOKEN,
  VERIFY_TOKEN,
  META_APP_SECRET,
  PORT = 3000,
} = process.env;

if (!VERIFY_TOKEN) {
  console.warn("VERIFY_TOKEN is missing. Webhook verification will fail.");
}
if (!PAGE_ACCESS_TOKEN) {
  console.warn("PAGE_ACCESS_TOKEN is missing. Replies will not be sent.");
}
if (!PAGE_ID) {
  console.warn("PAGE_ID is missing. Ensure Page is linked to Instagram.");
}

const app = express();

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

app.get("/", (req, res) => {
  res.status(200).send("ok");
});

function verifySignature(req, res, next) {
  if (!META_APP_SECRET) return next();
  const signature = req.headers["x-hub-signature-256"];
  if (!signature || !req.rawBody) {
    return res.sendStatus(401);
  }
  const expected =
    "sha256=" +
    crypto.createHmac("sha256", META_APP_SECRET).update(req.rawBody).digest("hex");
  if (signature !== expected) {
    return res.sendStatus(401);
  }
  return next();
}

app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

app.post("/webhook", verifySignature, async (req, res) => {
  const body = req.body;
  if (body.object !== "instagram") {
    return res.sendStatus(404);
  }
  try {
    const entries = body.entry || [];
    for (const entry of entries) {
      const messaging = entry.messaging || [];
      for (const event of messaging) {
        if (event.message && !event.message.is_echo) {
          const senderId = event.sender && event.sender.id;
          if (!senderId) continue;
          if (IG_USER_ID && senderId === IG_USER_ID) continue;
          const text =
            (event.message.text && event.message.text.trim()) ||
            "Hvala na poruci!";
          await sendMessage(senderId, text);
        }
      }
    }
    return res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err);
    return res.sendStatus(500);
  }
});

async function sendMessage(recipientId, text) {
  if (!PAGE_ACCESS_TOKEN) {
    console.warn("PAGE_ACCESS_TOKEN missing; cannot reply.");
    return;
  }
  const payload = {
    recipient: { id: recipientId },
    message: { text },
  };

  const url =
    "https://graph.facebook.com/v19.0/me/messages?access_token=" +
    encodeURIComponent(PAGE_ACCESS_TOKEN);

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    console.error("Send failed:", response.status, body);
  }
}

app.listen(PORT, () => {
  console.log("Webhook listening on port", PORT);
});
