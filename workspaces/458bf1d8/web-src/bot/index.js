import express from "express";

import { visit } from "./bot.js";

const PORT = "3000"

const app = express();

app.use(express.json());
app.use(express.static("public"));

app.post("/report", async (req, res) => {
  const { url } = req.body;
  if (
    typeof url !== "string" ||
    (!url.startsWith("http://") && !url.startsWith("https://"))
  ) {
    return res.status(400).send("Invalid url");
  }

  try {
    visit(url);
    return res.status(200).send(`Visiting...`);
  } catch (e) {
    return res.status(500).send(`Something went wrong: ${e}`);
  }
});

app.listen(PORT);