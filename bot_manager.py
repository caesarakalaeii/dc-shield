"""
Bot Manager - Integrates Discord bot with Quart application
Runs bot in background thread and provides interface for sending data
"""

import asyncio
import threading
from typing import Optional, Dict
import uuid
from logger import Logger

l = Logger()

class BotManager:
    """Manages Discord bot lifecycle and data communication"""

    def __init__(self):
        self.bot = None
        self.bot_thread = None
        self.loop = None
        self.ready = False

    def start_bot(self, token: str):
        """Start the Discord bot in a separate thread"""
        def run_bot_thread():
            """Thread function to run bot"""
            try:
                # Create new event loop for this thread
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)

                # Import and setup bot
                from discord_bot import SurveillanceBot, SurveillanceCommands, set_bot

                self.bot = SurveillanceBot()

                # Add commands and start bot
                async def setup_and_run():
                    await self.bot.add_cog(SurveillanceCommands(self.bot))

                    # Load config
                    from discord_bot import _load_config
                    config = _load_config()
                    if channel_id := config.get("surveillance_channel_id"):
                        self.bot.surveillance_channel_id = channel_id
                        l.info(f"Loaded surveillance channel: {channel_id}")

                    set_bot(self.bot)
                    l.info("Starting Discord bot connection...")

                    # Start bot (this will block until bot is running)
                    await self.bot.start(token)

                # Set ready flag when bot is connected (via on_ready event)
                @self.bot.event
                async def on_ready():
                    l.passing(f"Discord bot connected as {self.bot.user}")
                    l.passing(f"Bot is in {len(self.bot.guilds)} server(s)")
                    self.ready = True
                    # Start data processor
                    await self.bot.process_data_queue()

                self.loop.run_until_complete(setup_and_run())

            except Exception as e:
                l.error(f"Bot thread error: {e}")
                import traceback
                l.error(f"Bot thread traceback: {traceback.format_exc()}")

        # Start bot in background thread
        self.bot_thread = threading.Thread(target=run_bot_thread, daemon=True)
        self.bot_thread.start()
        l.info("Bot thread started")

    def send_data(self, data: Dict, recognition_info: Optional[Dict] = None):
        """Send surveillance data to Discord bot"""
        if not self.bot or not self.ready:
            l.warning("Bot not ready, cannot send data")
            return

        try:
            # Generate session ID
            session_id = str(uuid.uuid4())[:8]

            # Create data package
            data_package = {
                "data": data,
                "recognition_info": recognition_info,
                "session_id": session_id
            }

            # Queue data for bot to process
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self._async_queue_data(data_package),
                    self.loop
                )
                l.info(f"Queued data for session {session_id}")
            else:
                l.warning("Bot loop not running")

        except Exception as e:
            l.error(f"Error sending data to bot: {e}")

    async def _async_queue_data(self, data_package: Dict):
        """Async method to queue data"""
        if self.bot:
            self.bot.queue_data(data_package)

    def stop(self):
        """Stop the bot"""
        if self.bot and self.loop:
            asyncio.run_coroutine_threadsafe(self.bot.close(), self.loop)
            l.info("Bot stopped")

# Global bot manager instance
_bot_manager: Optional[BotManager] = None

def get_bot_manager() -> BotManager:
    """Get or create the global bot manager"""
    global _bot_manager
    if _bot_manager is None:
        _bot_manager = BotManager()
    return _bot_manager

def initialize_bot(token: str):
    """Initialize and start the bot"""
    manager = get_bot_manager()
    manager.start_bot(token)
    return manager
