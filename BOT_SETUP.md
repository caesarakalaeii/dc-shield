# 🤖 Discord Bot Setup Guide

## Overview

DC-Shield now includes an **interactive Discord bot** with menu-based navigation for exploring surveillance data. The bot replaces the webhook-only approach with a full-featured Discord application that supports buttons, dropdowns, and interactive data exploration.

## ✨ Features

### Interactive Menu Navigation
- **📊 Overview** - Main surveillance report with all data
- **🌍 Location** - GPS and location intelligence
- **📸 Camera** - Camera capture details
- **⚙️ Hardware** - Device hardware profile
- **📡 Network** - Network intelligence and WebRTC data
- **🔍 Fingerprint** - Canvas, WebGL, and audio fingerprinting
- **📜 Device History** - Cross-session tracking database
- **📄 Raw JSON** - Export raw data as file
- **🗑️ Delete** - Remove the message

### Slash Commands
- `/setchannel` - Set the channel for surveillance reports (Admin only)
- `/stats` - View device tracking statistics
- `/help` - Show bot help and command information

### Enhanced Features
- **Real-time data streaming** from web app to Discord
- **Persistent tracking** across sessions
- **Identity spoofing detection** alerts
- **Interactive data exploration** without message clutter
- **Session-based data storage** for pagination

## 🚀 Quick Start

### Prerequisites
1. Discord account with permissions to create bot applications
2. A Discord server where you want the bot
3. Python 3.11+ with discord.py installed

### Step 1: Create Discord Bot Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **"New Application"**
3. Give it a name (e.g., "DC-Shield Bot")
4. Go to the **"Bot"** section in the left sidebar
5. Click **"Add Bot"** and confirm
6. Under **"Privileged Gateway Intents"**, enable:
   - ☑️ Presence Intent
   - ☑️ Server Members Intent
   - ☑️ Message Content Intent
7. Click **"Save Changes"**

### Step 2: Get Your Bot Token

1. In the **"Bot"** section, click **"Reset Token"**
2. **Copy the token** - you'll only see this once!
3. ⚠️ **Keep this token secret** - treat it like a password

### Step 3: Invite Bot to Your Server

1. Go to **"OAuth2"** → **"URL Generator"** in the left sidebar
2. Under **"Scopes"**, select:
   - ☑️ `bot`
   - ☑️ `applications.commands`
3. Under **"Bot Permissions"**, select:
   - ☑️ Send Messages
   - ☑️ Send Messages in Threads
   - ☑️ Embed Links
   - ☑️ Attach Files
   - ☑️ Read Message History
   - ☑️ Use Slash Commands
4. Copy the generated URL at the bottom
5. Paste it in your browser and select your server
6. Click **"Authorize"**

### Step 4: Configure DC-Shield

Add your bot token to the configuration:

#### Option A: Using config.json
```json
{
  "dc_webhook_url": "https://discord.com/api/webhooks/...",
  "discord_bot_token": "YOUR_BOT_TOKEN_HERE",
  "default_server": "https://discord.gg/...",
  "honeypot_server": "https://discord.gg/...",
  "app_port": 8080,
  "test_flag": false
}
```

#### Option B: Using Environment Variables
```bash
export DISCORD_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
export DC_WEBHOOK_URL="https://discord.com/api/webhooks/..."
# ... other variables
```

### Step 5: Run the Application

```bash
# Install dependencies (if not already installed)
pip install -r requirements.txt

# Run the application
python main.py
```

You should see:
```
[INFO] Discord bot token found, initializing bot...
[PASS] Bot logged in as DC-Shield Bot
[PASS] Bot commands synced
[PASS] Discord bot initialized successfully
```

### Step 6: Set Surveillance Channel

In your Discord server, go to the channel where you want surveillance reports and run:

```
/setchannel
```

The bot will confirm:
```
>> [[ SURVEILLANCE CHANNEL CONFIGURED ]]
>> Channel set to: #surveillance
>> All surveillance data will be reported here
```

## 📖 Using the Bot

### Viewing Surveillance Data

When someone visits your DC-Shield link, the bot will automatically send an interactive message:

```
>> [[ SURVEILLANCE PROTOCOL ACTIVE ]]
>> BREACH_ANALYSIS_INITIATED
>> THREAT_LEVEL: ⚡ [[ HIGH_RISK ]]
>> DATA_EXPOSURE: 15/22 vectors compromised
```

Click the buttons below the embed to navigate:
- **Overview** - See the main report again
- **Location** - View GPS coordinates and map links
- **Camera** - See camera capture details
- **Hardware** - Explore device specifications
- **Network** - View network intel and IP data
- **Fingerprint** - See unique device identifiers
- **Device History** - View tracking database
- **Raw JSON** - Download complete data
- **Delete** - Remove the message

### Checking Statistics

View real-time tracking statistics:

```
/stats
```

Shows:
- Total devices tracked
- Total visits logged
- Returning visitors
- Identity spoofing attempts
- New devices

### Getting Help

```
/help
```

Displays:
- Available commands
- Button explanations
- Educational information

## 🔧 Advanced Configuration

### Bot Configuration File

The bot stores its configuration in `bot_config.json`:

```json
{
  "surveillance_channel_id": 1234567890123456789
}
```

This file is automatically created when you run `/setchannel`.

### Fallback Behavior

If the bot is not available, DC-Shield automatically falls back to webhook mode:

```python
# Bot available: Interactive menus
bot_manager.send_data(data, recognition_info)

# Bot unavailable: Fallback to webhook
send_to_channel(COMPREHENSIVE_REPORT_MESSAGE, embed)
```

### Running Bot Standalone

You can also run the bot independently:

```bash
python discord_bot.py YOUR_BOT_TOKEN
```

## 🎨 Customization

### Modify Button Layout

Edit `discord_bot.py` → `SurveillanceView._setup_buttons()`:

```python
def _setup_buttons(self):
    # Add custom button
    if self.data.get("custom_category"):
        self.add_item(
            CategoryButton(
                label="Custom",
                category="custom",
                style=discord.ButtonStyle.primary,
                emoji="🎯",
            )
        )
```

### Add New Slash Commands

Edit `discord_bot.py` → `SurveillanceCommands` class:

```python
@app_commands.command(name="clear", description="Clear all tracking data")
@app_commands.checks.has_permissions(administrator=True)
async def clear_data(self, interaction: discord.Interaction):
    tracker = get_tracker()
    tracker.device_history = {}
    tracker._save_history()
    await interaction.response.send_message("✅ Tracking data cleared!")
```

### Custom Embed Colors

Edit `surveillance_embeds.py` → `get_threat_indicator()`:

```python
def get_threat_indicator(score):
    if score >= 80:
        return "🔴 CRITICAL", 0xFF0000  # Red
    # ... customize colors here
```

## 🐛 Troubleshooting

### Bot Not Responding

**Problem**: Bot doesn't send messages or respond to commands

**Solutions**:
1. Check bot token is correct in config
2. Verify bot has necessary permissions (Send Messages, Embed Links)
3. Ensure bot is online (check Discord server member list)
4. Run `/setchannel` in your desired channel
5. Check logs for errors

### Commands Not Showing

**Problem**: Slash commands don't appear

**Solutions**:
1. Wait 5-10 minutes for Discord to sync commands
2. Kick and re-invite the bot
3. Check bot has `applications.commands` scope
4. Try in a different server

### "Bot not available, falling back to webhook"

**Problem**: System uses webhook instead of bot

**Solutions**:
1. Verify bot token in config
2. Check bot is running (see logs)
3. Ensure bot connected successfully
4. Check for startup errors

### Buttons Not Working

**Problem**: Clicking buttons does nothing

**Solutions**:
1. Check bot has "Use Application Commands" permission
2. Verify message is recent (views timeout after 1 hour)
3. Re-send the message (data expires)
4. Check bot logs for interaction errors

### Permission Errors

**Problem**: "Missing Permissions" or "Forbidden" errors

**Solutions**:
1. Re-invite bot with correct permissions
2. Check channel-specific permission overrides
3. Ensure bot role is above relevant roles
4. Grant "Embed Links" and "Attach Files" permissions

## 📊 Performance

### Resource Usage
- **Memory**: ~50-100 MB (bot) + ~30-50 MB (Quart app)
- **CPU**: Minimal (<1% idle, <5% during data processing)
- **Network**: ~1-5 KB per surveillance event

### Scaling
- Handles concurrent surveillance events via queue
- Session data stored in memory (up to 1000 sessions recommended)
- Bot runs in separate thread to avoid blocking web app

### Optimization Tips
1. Clean up old session data periodically
2. Limit embed field sizes for large datasets
3. Use ephemeral responses for sensitive data
4. Implement rate limiting for high-traffic scenarios

## 🔒 Security Best Practices

### Token Security
- ✅ Store token in environment variables or secure config
- ✅ Never commit tokens to version control
- ✅ Use `.gitignore` for `config.json` and `bot_config.json`
- ✅ Rotate tokens periodically
- ❌ Never share tokens publicly

### Permission Hardening
- Only grant necessary permissions
- Use channel-specific overrides
- Restrict `/setchannel` to administrators
- Implement rate limiting for commands

### Data Protection
- Sanitize data before display
- Truncate sensitive information
- Use ephemeral messages for private data
- Clear old session data regularly

## 📚 Further Reading

- [Discord.py Documentation](https://discordpy.readthedocs.io/)
- [Discord Bot Best Practices](https://discord.com/developers/docs/topics/community-resources)
- [Discord Developer Portal](https://discord.com/developers/applications)
- [DC-Shield Documentation](./README.MD)

## 🎓 Educational Use

This bot demonstrates:
- **Real-time data streaming** between applications
- **Interactive user interfaces** in Discord
- **Persistent device tracking** techniques
- **Browser fingerprinting** methods
- **Privacy implications** of web tracking

Remember: This is an **educational tool** for cybersecurity training. Always:
- Get consent before tracking
- Follow applicable laws (GDPR, CCPA)
- Secure stored data
- Provide opt-out mechanisms
- Use responsibly

---

**Version**: 1.0
**Last Updated**: 2025-10-16
**For Educational Purposes Only**
