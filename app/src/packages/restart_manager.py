"""Stability restart manager for scheduled and heuristic restarts."""

import asyncio
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from distutils.util import strtobool
from typing import Optional

logger = logging.getLogger("tgdel-restart-manager")

# Track last activity timestamp
_last_message_activity = time.time()
_activity_lock = asyncio.Lock()


async def update_last_activity():
    """Update the timestamp of last message activity."""
    global _last_message_activity
    async with _activity_lock:
        _last_message_activity = time.time()
        logger.log(
            5, f"Activity updated: {datetime.fromtimestamp(_last_message_activity)}"
        )


async def get_seconds_since_activity() -> float:
    """Get seconds elapsed since last activity."""
    async with _activity_lock:
        return time.time() - _last_message_activity


def restart_process_gracefully(exit_code: int = 0):
    """Restart the current process with the same command line.

    This uses a background shell script to restart after a short delay,
    allowing the current process to exit cleanly.
    """
    logger.warning(f"[restart] Initiating graceful restart with exit code {exit_code}")

    # Get the current command line arguments
    # Skip the first argument (python executable) if it's 'python' or 'python3'
    args = sys.argv
    if "python" in args[0].lower():
        args = args[1:]

    # Construct the restart command
    python_executable = sys.executable
    cmd_parts = [python_executable] + args
    cmd_str = " ".join(f'"{arg}"' if " " in arg else arg for arg in cmd_parts)

    logger.info(f"[restart] Command to restart: {cmd_str}")

    # Create a background restart script
    restart_script = f"""#!/bin/sh
sleep 2
exec {cmd_str}
"""

    # Write and execute restart script
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write(restart_script)
        script_path = f.name

    os.chmod(script_path, 0o755)

    logger.info(f"[restart] Spawning background restart script: {script_path}")

    # Detached process spawn
    subprocess.Popen(
        ["/bin/sh", script_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    logger.info(f"[restart] Background restart spawned, exiting current process")
    sys.exit(exit_code)


async def scheduled_restart_loop(
    cron_expression: Optional[str],
    stop_event: asyncio.Event,
):
    """Background loop that restarts the process on a cron schedule.

    Args:
        cron_expression: Cron expression like "0 4 * * *" for daily at 4 AM.
                       If None or empty, this loop is disabled.
        stop_event: Event to signal loop termination.
    """
    if not cron_expression:
        logger.info(
            "[restart-scheduled] No RESTART_CRON configured, skipping scheduled restart loop"
        )
        return

    try:
        from croniter import croniter
    except ImportError:
        logger.error(
            "[restart-scheduled] croniter not installed, cannot use RESTART_CRON"
        )
        logger.error("[restart-scheduled] Install with: pip install croniter")
        return

    logger.info(
        f"[restart-scheduled] Starting scheduled restart loop with cron: {cron_expression}"
    )

    try:
        cron = croniter(cron_expression, datetime.now())
        next_restart = cron.get_next(datetime)
        logger.info(f"[restart-scheduled] Next scheduled restart: {next_restart}")

        while True:
            # Calculate seconds until next restart
            now = datetime.now()
            if next_restart <= now:
                next_restart = cron.get_next(datetime)

            seconds_until_restart = (next_restart - now).total_seconds()

            if seconds_until_restart > 0:
                logger.info(
                    f"[restart-scheduled] Sleeping for {seconds_until_restart:.0f} seconds until {next_restart}"
                )

                # Wait with stop event check
                try:
                    await asyncio.wait_for(
                        stop_event.wait(), timeout=seconds_until_restart
                    )
                    # If we get here, stop_event was set
                    logger.info("[restart-scheduled] Stop event received, exiting loop")
                    break
                except asyncio.TimeoutError:
                    # Time to restart
                    pass

            # Perform restart
            logger.warning(
                f"[restart-scheduled] Executing scheduled restart at {datetime.now()}"
            )
            restart_process_gracefully(exit_code=0)
            return  # Never reached, but for clarity

    except Exception as e:
        logger.critical(
            f"[restart-scheduled] Error in scheduled restart loop: {e}", exc_info=True
        )


async def inactivity_restart_loop(
    inactivity_threshold_hours: Optional[int],
    stop_event: asyncio.Event,
):
    """Background loop that restarts the process if no message activity for N hours.

    Args:
        inactivity_threshold_hours: Hours of inactivity before restart.
                                   If None or 0, this loop is disabled.
        stop_event: Event to signal loop termination.
    """
    if not inactivity_threshold_hours or inactivity_threshold_hours <= 0:
        logger.info(
            "[restart-inactivity] No RESTART_AFTER_INACTIVITY_HOURS configured, skipping inactivity restart loop"
        )
        return

    threshold_seconds = inactivity_threshold_hours * 3600

    logger.info(f"[restart-inactivity] Starting inactivity restart loop")
    logger.info(
        f"[restart-inactivity] Threshold: {inactivity_threshold_hours} hours ({threshold_seconds} seconds)"
    )

    try:
        while True:
            seconds_inactive = await get_seconds_since_activity()
            seconds_remaining = threshold_seconds - seconds_inactive

            if seconds_inactive >= threshold_seconds:
                # Inactivity threshold exceeded - restart
                logger.warning(
                    f"[restart-inactivity] Inactivity threshold exceeded! "
                    f"Inactive for {seconds_inactive / 3600:.1f} hours. Restarting..."
                )
                restart_process_gracefully(exit_code=0)
                return

            # Sleep for a reasonable interval (check every 5 minutes or remaining time)
            sleep_seconds = min(300, max(10, seconds_remaining + 1))

            logger.log(
                5,
                f"[restart-inactivity] Inactive for {seconds_inactive / 60:.1f} minutes, "
                f"checking again in {sleep_seconds} seconds",
            )

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=sleep_seconds)
                logger.info("[restart-inactivity] Stop event received, exiting loop")
                break
            except asyncio.TimeoutError:
                continue  # Check again

    except Exception as e:
        logger.critical(
            f"[restart-inactivity] Error in inactivity restart loop: {e}", exc_info=True
        )


def get_restart_cron_from_env() -> Optional[str]:
    """Get the restart cron expression from environment."""
    cron = os.getenv("RESTART_CRON", "").strip()
    return cron if cron else None


def get_inactivity_hours_from_env() -> Optional[int]:
    """Get the inactivity threshold hours from environment."""
    hours_str = os.getenv("RESTART_AFTER_INACTIVITY_HOURS", "0").strip()
    try:
        hours = int(hours_str)
        return hours if hours > 0 else None
    except ValueError:
        return None
