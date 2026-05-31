import time
import threading
import datetime
import json
import os

# Feature 9: Scheduled Tasking
# A cron-like scheduler that allows PacketLoop sessions to be pre-programmed
# to run automatically at specific times or at regular intervals.
# Supports: once, interval, daily, and weekday scheduling.
# Schedule data is persisted in a JSON file for cross-session continuity.

SCHEDULE_FILE = "packetloop_schedule.json"

class Task:
    def __init__(self, name, callback, schedule_type, run_at, repeat=False, kwargs=None):
        """
        name          : Unique task identifier.
        callback      : Callable to execute.
        schedule_type : 'once', 'interval', 'daily', 'weekday'.
        run_at        : Time string "HH:MM" (daily/weekday) or interval in seconds (interval).
        repeat        : Whether to repeat after a 'once' or 'interval' task.
        kwargs        : Arguments to pass to the callback.
        """
        self.name = name
        self.callback = callback
        self.schedule_type = schedule_type
        self.run_at = run_at
        self.repeat = repeat
        self.kwargs = kwargs or {}
        self.last_run = None
        self.enabled = True

    def is_due(self):
        now = datetime.datetime.now()
        if self.schedule_type == "once":
            if self.last_run is None:
                target = datetime.datetime.strptime(self.run_at, "%Y-%m-%d %H:%M")
                return now >= target
            return False

        elif self.schedule_type == "interval":
            interval_secs = int(self.run_at)
            if self.last_run is None:
                return True
            return (now - self.last_run).total_seconds() >= interval_secs

        elif self.schedule_type == "daily":
            target_time = datetime.datetime.strptime(self.run_at, "%H:%M").time()
            if now.time().hour == target_time.hour and now.time().minute == target_time.minute:
                if self.last_run is None or self.last_run.date() < now.date():
                    return True
            return False

        elif self.schedule_type == "weekday":
            day, hhmm = self.run_at.split("/")
            day_map = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
            target_day = day_map.get(day.lower(), -1)
            target_time = datetime.datetime.strptime(hhmm, "%H:%M").time()
            if now.weekday() == target_day:
                if now.time().hour == target_time.hour and now.time().minute == target_time.minute:
                    if self.last_run is None or self.last_run.date() < now.date():
                        return True
            return False

        return False

    def execute(self):
        self.last_run = datetime.datetime.now()
        print(f"[Scheduler] Running task: '{self.name}'")
        try:
            self.callback(**self.kwargs)
        except Exception as e:
            print(f"[Scheduler] Task '{self.name}' raised an error: {e}")


class Scheduler:
    def __init__(self):
        self.tasks = []
        self._thread = None
        self._running = False

    def add_task(self, name, callback, schedule_type, run_at, repeat=False, **kwargs):
        """Adds a new task to the scheduler."""
        task = Task(name, callback, schedule_type, run_at, repeat, kwargs)
        self.tasks.append(task)
        print(f"[Scheduler] Task '{name}' registered. Type: {schedule_type}, At: {run_at}")
        return task

    def _run_loop(self):
        while self._running:
            for task in self.tasks:
                if task.enabled and task.is_due():
                    t = threading.Thread(target=task.execute, daemon=True)
                    t.start()
            time.sleep(30)  # Check every 30 seconds to avoid busy-waiting

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print(f"[Scheduler] Started. Monitoring {len(self.tasks)} task(s).")

    def stop(self):
        self._running = False
        print("[Scheduler] Stopped.")

    def list_tasks(self):
        """Prints a summary of all registered tasks."""
        print("\n[Scheduler] Registered Tasks:")
        print(f"{'Name':<20} {'Type':<12} {'At':<20} {'Last Run':<20} {'Enabled'}")
        print("-" * 80)
        for t in self.tasks:
            last = t.last_run.strftime("%Y-%m-%d %H:%M:%S") if t.last_run else "Never"
            print(f"{t.name:<20} {t.schedule_type:<12} {str(t.run_at):<20} {last:<20} {t.enabled}")
        print()
