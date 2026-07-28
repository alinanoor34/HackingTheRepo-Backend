import express from "express";
import User from "../models/User.js";
import { protect } from "../middleware/auth.js";
import { settingsSchema, validate } from "../middleware/validate.js";
import { decryptSecret, encryptSecret, maskSecret } from "../utils/crypto.js";

const router = express.Router();

// GET /api/settings
router.get("/", protect, async (req, res) => {
  const user = await User.findById(req.user._id);
  const githubToken = decryptSecret(user.githubToken);
  const openaiKey = decryptSecret(user.openaiKey);

  res.json({
    githubUsername: user.githubUsername,
    githubToken: githubToken ? maskSecret(user.githubToken) : "",
    openaiKey: openaiKey ? maskSecret(user.openaiKey) : "",
    hasGithubToken: !!githubToken,
    hasOpenaiKey: !!openaiKey,
  });
});

// PUT /api/settings
router.put("/", protect, validate(settingsSchema), async (req, res) => {
  try {
    const { githubUsername, githubToken, openaiKey } = req.body;
    const update = {};
    if (githubUsername !== undefined) update.githubUsername = githubUsername;
    if (githubToken && !githubToken.startsWith("••")) {
      update.githubToken = encryptSecret(githubToken);
    }
    if (openaiKey && !openaiKey.startsWith("••")) {
      update.openaiKey = encryptSecret(openaiKey);
    }

    if (Object.keys(update).length === 0) {
      return res.status(400).json({
        message: "No settings fields to update",
        code: "VALIDATION_ERROR",
      });
    }

    const user = await User.findByIdAndUpdate(req.user._id, update, {
      new: true,
    });
    res.json({
      message: "Settings updated",
      githubUsername: user.githubUsername,
    });
  } catch (err) {
    res.status(500).json({ message: err.message, code: "INTERNAL_ERROR" });
  }
});

export default router;
