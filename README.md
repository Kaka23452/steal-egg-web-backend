# Steal An Egg Discord Spawn Tracker — JustRunMy deployment

## Upload / deploy
1. Open JustRunMy.App and create an app using **Zip Upload**.
2. Upload `StealAnEgg_Discord_Backend_JustRunMy.zip`.
3. Use start command `npm start` (package uses `node server.js`). Runtime is Node.js 20+ and listens on `process.env.PORT`.
4. In the app's environment variables, set:
   - `DISCORD_BOT_TOKEN` — your bot token, kept only on the server
   - `DISCORD_CHANNEL_ID` — ID of the channel to monitor
   - `ALLOWED_ORIGIN` — `*` for initial testing; restrict later if you know the browser origin
5. In Discord Developer Portal → your app → Bot, enable **Message Content Intent**. Invite bot with View Channel and Read Message History permissions; ensure it can see the selected channel.
6. Deploy, then open `/health` on the assigned HTTPS app URL. It should report `ok: true`, `channelConfigured: true`, and `discordConnected: true`.
7. In V289 dashboard Admin Control → **Discord Spawn Tracker**, paste the HTTPS base URL (no `/api/schedule` suffix) and press **Connect & Start Sync**.

## Recognized message formats
- `Golden Dragon — 2m 30s`
- `Golden Dragon spawns in 00:45`
- `Golden Dragon: 1h 5m`
- `Pet: Golden Dragon | Timer: 5m 20s`

Parser only accepts explicit names + timer formats and ignores ambiguous messages. If your channel formats messages differently, share one sample message (without private data) so the parser can be adapted. The dashboard matches pet names exactly (case-insensitive) before updating visible CURRENT STOCK EGG timer text.

## Endpoints
- `GET /health` — backend and bot status
- `GET /api/schedule` — dashboard-compatible schedule feed
- `GET /api/spawns` — alias of schedule feed

## Important
- Your Discord incoming webhook is for sending messages, not reading channel history. This integration needs a Discord bot application/token.
- Never paste bot token into HTML or chat. Enter it only in JustRunMy environment variables.
- Schedule entries are held in memory and are cleared on service restart until fresh spawn messages arrive.
