"""
DC-Shield Discord Bot
Interactive bot with menu navigation for surveillance data
Educational cybersecurity demonstration tool
"""

import discord
from discord import app_commands
from discord.ext import commands
import json
import os
import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from surveillance_embeds import (
    create_combined_surveillance_embed,
    create_detailed_category_embed,
    get_threat_indicator,
)
from device_tracker import get_tracker
from logger import Logger

# Initialize logger
l = Logger()

# Bot configuration
INTENTS = discord.Intents.default()
INTENTS.message_content = True
INTENTS.members = True


class SurveillanceBot(commands.Bot):
    """DC-Shield Surveillance Bot with interactive menus"""

    def __init__(self):
        super().__init__(
            command_prefix="!",
            intents=INTENTS,
            help_command=None,
        )
        self.data_queue = asyncio.Queue()
        self.surveillance_channel_id = None
        self.session_data = {}  # Store session data for pagination

    async def setup_hook(self):
        """Initialize bot on startup"""
        await self.tree.sync()
        l.passing("Bot commands synced")

    async def on_ready(self):
        """Called when bot is ready"""
        l.passing(f"Bot logged in as {self.user}")
        l.passing(f"Bot ID: {self.user.id}")
        l.info(f"Servers: {len(self.guilds)}")

        # Start data processor task
        self.loop.create_task(self.process_data_queue())

    async def process_data_queue(self):
        """Process queued surveillance data"""
        while True:
            try:
                data_package = await self.data_queue.get()
                await self.send_surveillance_data(data_package)
            except Exception as e:
                l.error(f"Error processing data queue: {e}")
            await asyncio.sleep(0.1)

    async def send_surveillance_data(self, data_package: Dict):
        """Send surveillance data to Discord with interactive menu"""
        if not self.surveillance_channel_id:
            l.warning("Surveillance channel not configured")
            return

        channel = self.get_channel(self.surveillance_channel_id)
        if not channel:
            l.error(f"Channel {self.surveillance_channel_id} not found")
            return

        try:
            # Extract data from package
            collected_data = data_package.get("data", {})
            recognition_info = data_package.get("recognition_info")
            session_id = data_package.get("session_id")

            # Store data for pagination
            self.session_data[session_id] = {
                "data": collected_data,
                "recognition_info": recognition_info,
                "timestamp": datetime.now().isoformat(),
            }

            # Create main embed
            embed_dict = create_combined_surveillance_embed(
                collected_data, recognition_info
            )
            embed = self._dict_to_embed(embed_dict)

            # Create interactive view
            view = SurveillanceView(self, session_id, collected_data, recognition_info)

            # Send message with view
            await channel.send(embed=embed, view=view)
            l.passing(f"Sent surveillance data for session {session_id}")

        except Exception as e:
            l.error(f"Error sending surveillance data: {e}")

    def _dict_to_embed(self, embed_dict: Dict) -> discord.Embed:
        """Convert embed dictionary to Discord Embed object"""
        embed = discord.Embed(
            title=embed_dict.get("title", ""),
            description=embed_dict.get("description", ""),
            color=embed_dict.get("color", 0x00FF00),
            timestamp=datetime.fromisoformat(embed_dict.get("timestamp"))
            if embed_dict.get("timestamp")
            else None,
        )

        # Add fields
        for field in embed_dict.get("fields", []):
            embed.add_field(
                name=field.get("name", ""),
                value=field.get("value", "")[:1024],  # Discord limit
                inline=field.get("inline", False),
            )

        # Add footer
        if footer := embed_dict.get("footer"):
            embed.set_footer(
                text=footer.get("text", ""), icon_url=footer.get("icon_url")
            )

        return embed

    def queue_data(self, data_package: Dict):
        """Queue surveillance data for processing"""
        try:
            self.data_queue.put_nowait(data_package)
        except asyncio.QueueFull:
            l.warning("Data queue full, dropping data")


class SurveillanceView(discord.ui.View):
    """Interactive view for surveillance data navigation"""

    def __init__(
        self, bot: SurveillanceBot, session_id: str, data: Dict, recognition_info: Dict
    ):
        super().__init__(timeout=3600)  # 1 hour timeout
        self.bot = bot
        self.session_id = session_id
        self.data = data
        self.recognition_info = recognition_info
        self.current_page = 0

        # Add buttons based on available data
        self._setup_buttons()

    def _setup_buttons(self):
        """Setup buttons based on available data categories"""
        # Always show overview
        self.add_item(
            OverviewButton(
                label="Overview",
                style=discord.ButtonStyle.primary,
                emoji="📊",
            )
        )

        # Add category buttons
        if self.data.get("geolocation"):
            self.add_item(
                CategoryButton(
                    label="Location",
                    category="location",
                    style=discord.ButtonStyle.danger,
                    emoji="🌍",
                )
            )

        if self.data.get("camera", {}).get("captured"):
            self.add_item(
                CategoryButton(
                    label="Camera",
                    category="camera",
                    style=discord.ButtonStyle.danger,
                    emoji="📸",
                )
            )

        if self.data.get("screen") or self.data.get("canvas") or self.data.get("webgl"):
            self.add_item(
                CategoryButton(
                    label="Hardware",
                    category="hardware",
                    style=discord.ButtonStyle.secondary,
                    emoji="⚙️",
                )
            )

        if self.data.get("network") or self.data.get("webrtc"):
            self.add_item(
                CategoryButton(
                    label="Network",
                    category="network",
                    style=discord.ButtonStyle.secondary,
                    emoji="📡",
                )
            )

        if self.data.get("canvas") or self.data.get("audioFingerprint"):
            self.add_item(
                CategoryButton(
                    label="Fingerprint",
                    category="fingerprint",
                    style=discord.ButtonStyle.secondary,
                    emoji="🔍",
                )
            )

        # Add device history button
        self.add_item(
            DeviceHistoryButton(
                label="Device History",
                style=discord.ButtonStyle.success,
                emoji="📜",
            )
        )

        # Add raw data button
        self.add_item(
            RawDataButton(
                label="Raw JSON",
                style=discord.ButtonStyle.secondary,
                emoji="📄",
            )
        )

        # Add delete button
        self.add_item(
            DeleteButton(
                label="Delete",
                style=discord.ButtonStyle.danger,
                emoji="🗑️",
            )
        )


class OverviewButton(discord.ui.Button):
    """Button to show main overview"""

    async def callback(self, interaction: discord.Interaction):
        view: SurveillanceView = self.view
        embed_dict = create_combined_surveillance_embed(
            view.data, view.recognition_info
        )
        embed = view.bot._dict_to_embed(embed_dict)
        await interaction.response.edit_message(embed=embed, view=view)


class CategoryButton(discord.ui.Button):
    """Button for specific data category"""

    def __init__(self, label: str, category: str, **kwargs):
        super().__init__(label=label, **kwargs)
        self.category = category

    async def callback(self, interaction: discord.Interaction):
        view: SurveillanceView = self.view
        embed_dict = create_detailed_category_embed(view.data, self.category)
        embed = view.bot._dict_to_embed(embed_dict)
        await interaction.response.edit_message(embed=embed, view=view)


class DeviceHistoryButton(discord.ui.Button):
    """Button to show device history"""

    async def callback(self, interaction: discord.Interaction):
        view: SurveillanceView = self.view

        # Get device tracker
        tracker = get_tracker()
        stats = tracker.get_statistics()

        embed = discord.Embed(
            title=">> [[ DEVICE TRACKING DATABASE ]]",
            description="```ansi\n[0;32m>> PERSISTENT SURVEILLANCE STATISTICS\n[0;37m>> Educational demonstration of cross-session tracking```",
            color=0x00FF00,
            timestamp=datetime.now(),
        )

        # Add statistics
        embed.add_field(
            name=">> [[ DATABASE METRICS ]]",
            value=f"""```
>> TOTAL_DEVICES_TRACKED: {stats['total_unique_devices']}
>> TOTAL_VISITS_LOGGED: {stats['total_visits']}
>> RETURNING_VISITORS: {stats['returning_devices']}
>> IDENTITY_SPOOFING_DETECTED: {stats['devices_with_multiple_names']}
>> NEW_DEVICES_TODAY: {stats['new_devices']}```""",
            inline=False,
        )

        # Show device history for current session if available
        if view.recognition_info and view.recognition_info.get("is_returning"):
            history_value = "```ansi\n[0;33m>> CURRENT DEVICE HISTORY:\n[0;37m"
            history_value += f">> VISIT_COUNT: {view.recognition_info.get('visit_count', 0)}\n"
            history_value += f">> FIRST_SEEN: {view.recognition_info.get('first_seen', 'Unknown')[:16]}\n"
            history_value += f">> LAST_SEEN: {view.recognition_info.get('last_seen', 'Unknown')[:16]}\n"

            if view.recognition_info.get("is_new_name"):
                history_value += "\n[0;31m>> IDENTITIES_USED:\n[0;37m"
                for name in view.recognition_info.get("previous_names", []):
                    history_value += f"   └─ {name}\n"
                history_value += f"   └─ {view.recognition_info.get('current_name')} [CURRENT]\n"

            history_value += "```"

            embed.add_field(
                name=">> [[ SESSION TRACKING ]]", value=history_value, inline=False
            )

        embed.set_footer(
            text="DC-Shield Persistent Tracking • Educational Use Only",
            icon_url=None,
        )

        await interaction.response.edit_message(embed=embed, view=view)


class RawDataButton(discord.ui.Button):
    """Button to show raw JSON data"""

    async def callback(self, interaction: discord.Interaction):
        view: SurveillanceView = self.view

        try:
            # Format JSON data
            json_data = json.dumps(view.data, indent=2, default=str)

            # Split if too long (Discord has 2000 char limit for messages, 1024 for fields)
            if len(json_data) > 1900:
                # Send as file - need to use BytesIO for discord.File
                import io
                json_bytes = io.BytesIO(json_data.encode('utf-8'))

                await interaction.response.send_message(
                    content=">> [[ RAW DATA EXPORT ]]\n```Full surveillance data attached as JSON file```",
                    file=discord.File(
                        fp=json_bytes,
                        filename=f"surveillance_data_{view.session_id}.json",
                    ),
                    ephemeral=True,
                )
            else:
                embed = discord.Embed(
                    title=">> [[ RAW DATA DUMP ]]",
                    description=f"```json\n{json_data}```",
                    color=0x00AA00,
                    timestamp=datetime.now(),
                )
                embed.set_footer(text=f"Session ID: {view.session_id}")
                await interaction.response.send_message(embed=embed, ephemeral=True)

        except Exception as e:
            l.error(f"Error in raw JSON button: {e}")
            await interaction.response.send_message(
                f">> [[ ERROR ]]\n```Failed to export data: {str(e)}```",
                ephemeral=True
            )


class DeleteButton(discord.ui.Button):
    """Button to delete the message"""

    async def callback(self, interaction: discord.Interaction):
        await interaction.message.delete()
        await interaction.response.send_message(
            ">> [[ MESSAGE_DELETED ]]", ephemeral=True, delete_after=3
        )


# Slash commands
class SurveillanceCommands(commands.Cog):
    """Slash commands for the surveillance bot"""

    def __init__(self, bot: SurveillanceBot):
        self.bot = bot

    @app_commands.command(
        name="setchannel", description="Set the channel for surveillance reports"
    )
    @app_commands.checks.has_permissions(administrator=True)
    async def set_channel(self, interaction: discord.Interaction):
        """Set current channel as surveillance channel"""
        self.bot.surveillance_channel_id = interaction.channel_id

        # Save to config
        _save_config({"surveillance_channel_id": interaction.channel_id})

        embed = discord.Embed(
            title=">> [[ SURVEILLANCE CHANNEL CONFIGURED ]]",
            description=f"```ansi\n[0;32m>> Channel set to: {interaction.channel.mention}\n>> All surveillance data will be reported here```",
            color=0x00FF00,
        )
        await interaction.response.send_message(embed=embed)
        l.passing(f"Surveillance channel set to {interaction.channel_id}")

    @app_commands.command(
        name="stats", description="View surveillance statistics"
    )
    async def stats(self, interaction: discord.Interaction):
        """Show device tracking statistics"""
        tracker = get_tracker()
        stats = tracker.get_statistics()

        embed = discord.Embed(
            title=">> [[ SURVEILLANCE STATISTICS ]]",
            description="```ansi\n[0;32m>> REAL-TIME TRACKING METRICS\n[0;37m>> Educational demonstration```",
            color=0x00FF00,
            timestamp=datetime.now(),
        )

        embed.add_field(
            name=">> [[ DATABASE METRICS ]]",
            value=f"""```
Total Devices Tracked: {stats['total_unique_devices']}
Total Visits Logged: {stats['total_visits']}
Returning Visitors: {stats['returning_devices']}
Identity Spoofing: {stats['devices_with_multiple_names']}
New Devices: {stats['new_devices']}```""",
            inline=False,
        )

        embed.set_footer(
            text="DC-Shield Statistics • Educational Use Only", icon_url=None
        )

        await interaction.response.send_message(embed=embed)

    @app_commands.command(
        name="help", description="Show help information"
    )
    async def help_command(self, interaction: discord.Interaction):
        """Show help information"""
        embed = discord.Embed(
            title=">> [[ DC-SHIELD BOT HELP ]]",
            description="```ansi\n[0;32m>> INTERACTIVE SURVEILLANCE SYSTEM\n[0;37m>> Educational cybersecurity demonstration tool```",
            color=0x00FF00,
        )

        embed.add_field(
            name=">> [[ COMMANDS ]]",
            value="""```
/setchannel  - Set surveillance report channel (Admin)
/stats       - View tracking statistics
/help        - Show this help message```""",
            inline=False,
        )

        embed.add_field(
            name=">> [[ INTERACTIVE FEATURES ]]",
            value="""```
📊 Overview      - Main surveillance report
🌍 Location      - GPS and location data
📸 Camera        - Camera capture details
⚙️ Hardware      - Device hardware profile
📡 Network       - Network intelligence
🔍 Fingerprint   - Device fingerprinting
📜 Device History - Cross-session tracking
📄 Raw JSON      - Export raw data
🗑️ Delete        - Remove message```""",
            inline=False,
        )

        embed.add_field(
            name=">> [[ EDUCATIONAL PURPOSE ]]",
            value="This tool demonstrates browser fingerprinting, device tracking, and data collection techniques for cybersecurity education.",
            inline=False,
        )

        embed.set_footer(
            text="DC-Shield Interactive Bot • For Educational Use Only", icon_url=None
        )

        await interaction.response.send_message(embed=embed)


def _save_config(config_data: Dict):
    """Save configuration to file"""
    config_file = "bot_config.json"
    try:
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                existing_config = json.load(f)
            existing_config.update(config_data)
        else:
            existing_config = config_data

        with open(config_file, "w") as f:
            json.dump(existing_config, f, indent=2)
    except Exception as e:
        l.error(f"Failed to save config: {e}")


def _load_config() -> Dict:
    """Load configuration from file"""
    config_file = "bot_config.json"
    try:
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                return json.load(f)
    except Exception as e:
        l.error(f"Failed to load config: {e}")
    return {}


async def run_bot(token: str):
    """Run the Discord bot"""
    bot = SurveillanceBot()

    # Add commands
    await bot.add_cog(SurveillanceCommands(bot))

    # Load saved config
    config = _load_config()
    if channel_id := config.get("surveillance_channel_id"):
        bot.surveillance_channel_id = channel_id
        l.info(f"Loaded surveillance channel: {channel_id}")

    # Run bot
    try:
        await bot.start(token)
    except Exception as e:
        l.error(f"Bot error: {e}")
        raise


# Export bot instance for use in main.py
_bot_instance: Optional[SurveillanceBot] = None


def get_bot() -> Optional[SurveillanceBot]:
    """Get the bot instance"""
    return _bot_instance


def set_bot(bot: SurveillanceBot):
    """Set the bot instance"""
    global _bot_instance
    _bot_instance = bot


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python discord_bot.py <bot_token>")
        sys.exit(1)

    token = sys.argv[1]
    asyncio.run(run_bot(token))
