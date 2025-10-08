import os
import sys
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import winreg
import subprocess
import threading
import shutil
import queue
import time
import re
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional, Callable, Dict, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET
import tempfile
import uuid
import schedule
from datetime import datetime, timedelta
import psutil
import asyncio
from enum import Enum
import logging
from datetime import datetime
# === Data Classes ===
@dataclass
class ProgramInfo:
    name: str
    uninstall_command: str
    install_location: str = ""
    publisher: str = ""
    version: str = ""
    size: str = ""
    install_date: str = ""

@dataclass
class StartupItem:
    name: str
    path: str
    hive: int
    registry_path: str

@dataclass
class LeftoverItem:
    path: Path
    item_type: str  # 'file', 'folder', 'registry'
    size: int = 0
    category: str = ""  # 'program_files', 'appdata', 'registry', 'temp', 'shortcuts'
    confidence: str = "Low"  # High, Medium, Low

@dataclass
class DeepScanResult:
    program_name: str
    leftover_items: List[LeftoverItem]
    total_size: int
    scan_time: float

@dataclass
class ProgressUpdate:
    current: int
    total: int
    message: str

@dataclass
class VirusScanResult:
    file_path: str
    threat_name: str
    severity: str  # Severe, High, Medium, Low
    action_taken: str  # None, Quarantined, Removed, Allowed

class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"
    SCAN = "SCAN"
    SECURITY = "SECURITY"

@dataclass
class LogMessage:
    message: str
    level: LogLevel
    timestamp: str

# === Smart Automation System ===
class OptimizationProfile(Enum):
    GAMING = "gaming"
    WORK = "work"
    PRIVACY = "privacy"
    PERFORMANCE = "performance"
    MAINTENANCE = "maintenance"

class TaskPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class AutomationTask:
    """Represents an automated task"""
    id: str
    name: str
    description: str
    profile: OptimizationProfile
    priority: TaskPriority
    enabled: bool = True
    last_run: Optional[datetime] = None
    success_count: int = 0
    error_count: int = 0
    function: Optional[Callable] = None
    parameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScheduledTask:
    """Represents a scheduled automation task"""
    task_id: str
    schedule_type: str  # 'daily', 'weekly', 'monthly', 'interval'
    schedule_time: str  # '14:30', '*/15' for intervals
    days: List[str] = field(default_factory=list)  # ['monday', 'wednesday']
    enabled: bool = True
    next_run: Optional[datetime] = None

@dataclass
class AutomationResult:
    """Result of an automation task"""
    task_id: str
    success: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

class SmartAutomation:
    """Advanced automation system with intelligent profiles and scheduling"""
    
    def __init__(self, config_path: Optional[Path] = None, logger=None):
        self.config_path = config_path or Path.home() / ".pyuninstallx" / "automation_config.json"
        self.config_path.parent.mkdir(exist_ok=True)
        self.logger = logger
        
        # Task storage
        self.tasks: Dict[str, AutomationTask] = {}
        self.scheduled_tasks: Dict[str, ScheduledTask] = {}
        self.results_history: List[AutomationResult] = []
        
        # Automation state
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.task_complete_callbacks: List[Callable[[AutomationResult], None]] = []
        
        # Initialize built-in tasks
        self._initialize_builtin_tasks()
        self.load_config()
        
        # Start scheduler
        self.start_scheduler()
    
    def _initialize_builtin_tasks(self):
        """Initialize built-in automation tasks"""
        
        # Gaming Mode Tasks
        self.tasks["gaming_disable_services"] = AutomationTask(
            id="gaming_disable_services",
            name="Disable Background Services",
            description="Temporarily disable non-essential services for gaming",
            profile=OptimizationProfile.GAMING,
            priority=TaskPriority.HIGH,
            function=self._disable_background_services,
            parameters={"gaming_mode": True}
        )
        
        self.tasks["gaming_priority_boost"] = AutomationTask(
            id="gaming_priority_boost",
            name="Boost Gaming Performance",
            description="Optimize system settings for gaming performance",
            profile=OptimizationProfile.GAMING,
            priority=TaskPriority.HIGH,
            function=self._boost_gaming_performance
        )
        
        # Work Mode Tasks
        self.tasks["work_productivity_apps"] = AutomationTask(
            id="work_productivity_apps",
            name="Launch Productivity Apps",
            description="Start essential work applications",
            profile=OptimizationProfile.WORK,
            priority=TaskPriority.NORMAL,
            function=self._launch_productivity_apps,
            parameters={"apps": ["notepad", "calc"]}
        )
        
        self.tasks["work_focus_mode"] = AutomationTask(
            id="work_focus_mode",
            name="Enable Focus Mode",
            description="Block distracting websites and applications",
            profile=OptimizationProfile.WORK,
            priority=TaskPriority.NORMAL,
            function=self._enable_focus_mode
        )
        
        # Privacy Mode Tasks
        self.tasks["privacy_clear_history"] = AutomationTask(
            id="privacy_clear_history",
            name="Clear Browsing History",
            description="Clear browser history, cookies, and temporary files",
            profile=OptimizationProfile.PRIVACY,
            priority=TaskPriority.HIGH,
            function=self._clear_privacy_data
        )
        
        self.tasks["privacy_secure_delete"] = AutomationTask(
            id="privacy_secure_delete",
            name="Secure Delete Temp Files",
            description="Securely delete temporary and sensitive files",
            profile=OptimizationProfile.PRIVACY,
            priority=TaskPriority.HIGH,
            function=self._secure_delete_temp_files
        )
        
        # Performance Mode Tasks
        self.tasks["performance_cleanup"] = AutomationTask(
            id="performance_cleanup",
            name="System Cleanup",
            description="Clean temporary files and optimize system",
            profile=OptimizationProfile.PERFORMANCE,
            priority=TaskPriority.NORMAL,
            function=self._performance_cleanup
        )
        
        self.tasks["performance_defrag"] = AutomationTask(
            id="performance_defrag",
            name="Disk Optimization",
            description="Optimize disk fragmentation",
            profile=OptimizationProfile.PERFORMANCE,
            priority=TaskPriority.LOW,
            function=self._disk_optimization
        )
        
        # Maintenance Mode Tasks
        self.tasks["maintenance_health_check"] = AutomationTask(
            id="maintenance_health_check",
            name="System Health Check",
            description="Perform comprehensive system health analysis",
            profile=OptimizationProfile.MAINTENANCE,
            priority=TaskPriority.NORMAL,
            function=self._system_health_check
        )
        
        self.tasks["maintenance_update_check"] = AutomationTask(
            id="maintenance_update_check",
            name="Check for Updates",
            description="Check for system and software updates",
            profile=OptimizationProfile.MAINTENANCE,
            priority=TaskPriority.LOW,
            function=self._check_updates
        )
    
    def apply_profile(self, profile: OptimizationProfile, interactive: bool = True) -> List[AutomationResult]:
        """Apply an optimization profile by running all associated tasks"""
        results = []
        profile_tasks = [task for task in self.tasks.values() if task.profile == profile and task.enabled]
        
        # Sort by priority
        profile_tasks.sort(key=lambda t: t.priority.value, reverse=True)
        
        if interactive:
            task_names = [task.name for task in profile_tasks]
            response = messagebox.askyesno(
                f"Apply {profile.value.title()} Profile",
                f"This will execute the following tasks:\n\n" + "\n".join(f"• {name}" for name in task_names) + 
                f"\n\nDo you want to continue?"
            )
            if not response:
                return results
        
        self._log(f"Applying {profile.value.title()} profile with {len(profile_tasks)} tasks")
        
        for task in profile_tasks:
            result = self._execute_task(task)
            results.append(result)
            
            # Notify callbacks
            for callback in self.task_complete_callbacks:
                try:
                    callback(result)
                except Exception:
                    pass
        
        self._log(f"Profile {profile.value.title()} applied. {sum(1 for r in results if r.success)}/{len(results)} tasks succeeded")
        return results
    
    def _execute_task(self, task: AutomationTask) -> AutomationResult:
        """Execute a single automation task"""
        start_time = time.time()
        
        try:
            self._log(f"Executing task: {task.name}")
            
            if task.function:
                result = task.function(**task.parameters)
                success = result if isinstance(result, bool) else True
                message = "Task completed successfully"
                details = result if isinstance(result, dict) else {}
            else:
                success = False
                message = "Task function not implemented"
                details = {}
            
            # Update task statistics
            if success:
                task.success_count += 1
            else:
                task.error_count += 1
            
            task.last_run = datetime.now()
            
        except Exception as e:
            success = False
            message = f"Task failed: {str(e)}"
            details = {"error": str(e)}
            task.error_count += 1
            self._log(f"Task {task.name} failed: {e}")
        
        execution_time = time.time() - start_time
        
        result = AutomationResult(
            task_id=task.id,
            success=success,
            message=message,
            details=details,
            execution_time=execution_time
        )
        
        self.results_history.append(result)
        
        # Keep only last 100 results
        if len(self.results_history) > 100:
            self.results_history = self.results_history[-100:]
        
        return result
    
    # Task Implementation Methods
    def _disable_background_services(self, gaming_mode: bool = True) -> bool:
        """Disable non-essential background services"""
        try:
            # Services safe to temporarily disable for gaming
            gaming_services = [
                "Fax", "Spooler", "Themes", "TabletInputService",
                "WMPNetworkSvc", "WSearch"  # Windows Search can be heavy
            ]
            
            for service_name in gaming_services:
                try:
                    subprocess.run(
                        ["sc", "config", service_name, "start=disabled"],
                        capture_output=True,
                        check=False
                    )
                except Exception:
                    continue
            
            return True
        except Exception:
            return False
    
    def _boost_gaming_performance(self) -> bool:
        """Apply gaming performance optimizations"""
        try:
            # Set high performance power plan
            subprocess.run(
                ["powercfg", "/setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"],
                capture_output=True,
                check=False
            )
            
            # Disable Windows Game Mode (can cause issues)
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\GameBar", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "AutoGameModeEnabled", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
            except Exception:
                pass
            
            return True
        except Exception:
            return False
    
    def _launch_productivity_apps(self, apps: List[str]) -> bool:
        """Launch productivity applications"""
        try:
            for app in apps:
                try:
                    subprocess.Popen(app, shell=True)
                except Exception:
                    continue
            return True
        except Exception:
            return False
    
    def _enable_focus_mode(self) -> bool:
        """Enable focus mode by limiting distractions"""
        try:
            # Enable Do Not Disturb
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings", 
                                   0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
            except Exception:
                pass
            
            return True
        except Exception:
            return False
    
    def _clear_privacy_data(self) -> Dict[str, Any]:
        """Clear privacy-sensitive data"""
        results = {"cleared_items": 0, "errors": 0}
        
        try:
            # Clear Windows Run history
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", 
                                   0, winreg.KEY_SET_VALUE)
                
                # Get all values and delete them
                i = 0
                while True:
                    try:
                        value_name = winreg.EnumValue(key, i)[0]
                        if value_name != "MRUList":
                            winreg.DeleteValue(key, value_name)
                            results["cleared_items"] += 1
                        i += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
            except Exception:
                results["errors"] += 1
            
            # Clear recent documents
            try:
                recent_docs_path = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
                if recent_docs_path.exists():
                    for file in recent_docs_path.glob("*"):
                        try:
                            file.unlink()
                            results["cleared_items"] += 1
                        except Exception:
                            results["errors"] += 1
            except Exception:
                results["errors"] += 1
            
            return results
        except Exception:
            return {"cleared_items": 0, "errors": 1}
    
    def _secure_delete_temp_files(self) -> Dict[str, Any]:
        """Securely delete temporary files"""
        results = {"deleted_files": 0, "freed_space_mb": 0, "errors": 0}
        
        temp_dirs = [
            Path(os.environ.get("TEMP", "")),
            Path(os.environ.get("TMP", "")),
            Path("C:/Windows/Temp"),
            Path.home() / "AppData" / "Local" / "Temp"
        ]
        
        for temp_dir in temp_dirs:
            if not temp_dir.exists():
                continue
                
            try:
                for file in temp_dir.rglob("*"):
                    if file.is_file():
                        try:
                            size = file.stat().st_size
                            file.unlink()
                            results["deleted_files"] += 1
                            results["freed_space_mb"] += size / 1024 / 1024
                        except Exception:
                            results["errors"] += 1
            except Exception:
                results["errors"] += 1
        
        return results
    
    def _performance_cleanup(self) -> Dict[str, Any]:
        """Perform system performance cleanup"""
        results = {"actions_completed": 0}
        
        try:
            # Run disk cleanup
            try:
                subprocess.run(["cleanmgr", "/sagerun:1"], 
                             capture_output=True, timeout=300, check=False)
                results["actions_completed"] += 1
            except Exception:
                pass
            
            # Clear DNS cache
            try:
                subprocess.run(["ipconfig", "/flushdns"], 
                             capture_output=True, check=False)
                results["actions_completed"] += 1
            except Exception:
                pass
            
            return results
        except Exception:
            return {"actions_completed": 0}
    
    def _disk_optimization(self) -> bool:
        """Optimize disk performance"""
        try:
            # Run defrag on C: drive (if HDD)
            subprocess.run(["defrag", "C:", "/O"], 
                         capture_output=True, timeout=1800, check=False)
            return True
        except Exception:
            return False
    
    def _system_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive system health check"""
        results = {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "process_count": len(psutil.pids()),
            "uptime_hours": (time.time() - psutil.boot_time()) / 3600,
            "health_score": 100
        }
        
        # Calculate health score
        if results["cpu_usage"] > 80:
            results["health_score"] -= 20
        if results["memory_usage"] > 85:
            results["health_score"] -= 25
        if results["disk_usage"] > 90:
            results["health_score"] -= 30
        
        results["health_score"] = max(0, results["health_score"])
        
        return results
    
    def _check_updates(self) -> Dict[str, Any]:
        """Check for system and software updates"""
        results = {"updates_available": False, "update_count": 0}
        
        try:
            # Check Windows Updates (simplified)
            result = subprocess.run(
                ["powershell", "Get-WindowsUpdate"], 
                capture_output=True, text=True, timeout=30, check=False
            )
            
            if result.stdout and len(result.stdout.strip()) > 0:
                results["updates_available"] = True
                results["update_count"] = result.stdout.count('\n')
            
        except Exception:
            pass
        
        return results
    
    # Scheduling Methods
    def schedule_task(self, task_id: str, schedule_type: str, schedule_time: str, 
                     days: Optional[List[str]] = None) -> bool:
        """Schedule a task for automatic execution"""
        if task_id not in self.tasks:
            return False
        
        scheduled_task = ScheduledTask(
            task_id=task_id,
            schedule_type=schedule_type,
            schedule_time=schedule_time,
            days=days or [],
            enabled=True
        )
        
        self.scheduled_tasks[f"{task_id}_{schedule_type}"] = scheduled_task
        self._setup_schedule(scheduled_task)
        self.save_config()
        
        return True
    
    def _setup_schedule(self, scheduled_task: ScheduledTask):
        """Setup the actual schedule using the schedule library"""
        task = self.tasks.get(scheduled_task.task_id)
        if not task:
            return
        
        def run_scheduled_task():
            if scheduled_task.enabled:
                result = self._execute_task(task)
                for callback in self.task_complete_callbacks:
                    try:
                        callback(result)
                    except Exception:
                        pass
        
        if scheduled_task.schedule_type == "daily":
            schedule.every().day.at(scheduled_task.schedule_time).do(run_scheduled_task)
        elif scheduled_task.schedule_type == "weekly":
            for day in scheduled_task.days:
                getattr(schedule.every(), day.lower()).at(scheduled_task.schedule_time).do(run_scheduled_task)
        elif scheduled_task.schedule_type == "interval":
            # Parse interval (e.g., "*/15" for every 15 minutes)
            if scheduled_task.schedule_time.startswith("*/"):
                minutes = int(scheduled_task.schedule_time[2:])
                schedule.every(minutes).minutes.do(run_scheduled_task)
    
    def start_scheduler(self):
        """Start the task scheduler"""
        if self.is_running:
            return
        
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop the task scheduler"""
        self.is_running = False
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=2.0)
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.is_running:
            schedule.run_pending()
            time.sleep(1)
    
    def _log(self, message: str):
        """Log a message"""
        if self.logger:
            try:
                self.logger.log(message, "INFO")
            except Exception:
                pass
        print(f"[Automation] {message}")
    
    # Configuration Methods
    def save_config(self):
        """Save automation configuration"""
        config = {
            "tasks": {},
            "scheduled_tasks": {},
            "settings": {
                "auto_apply_profiles": False,
                "notification_enabled": True
            }
        }
        
        # Save task states (enabled/disabled, counts)
        for task_id, task in self.tasks.items():
            config["tasks"][task_id] = {
                "enabled": task.enabled,
                "success_count": task.success_count,
                "error_count": task.error_count,
                "last_run": task.last_run.isoformat() if task.last_run else None
            }
        
        # Save scheduled tasks
        for schedule_id, scheduled_task in self.scheduled_tasks.items():
            config["scheduled_tasks"][schedule_id] = {
                "task_id": scheduled_task.task_id,
                "schedule_type": scheduled_task.schedule_type,
                "schedule_time": scheduled_task.schedule_time,
                "days": scheduled_task.days,
                "enabled": scheduled_task.enabled
            }
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass
    
    def load_config(self):
        """Load automation configuration"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                
                # Load task states
                for task_id, task_config in config.get("tasks", {}).items():
                    if task_id in self.tasks:
                        task = self.tasks[task_id]
                        task.enabled = task_config.get("enabled", True)
                        task.success_count = task_config.get("success_count", 0)
                        task.error_count = task_config.get("error_count", 0)
                        
                        last_run = task_config.get("last_run")
                        if last_run:
                            try:
                                task.last_run = datetime.fromisoformat(last_run)
                            except Exception:
                                pass
                
                # Load scheduled tasks
                for schedule_id, schedule_config in config.get("scheduled_tasks", {}).items():
                    scheduled_task = ScheduledTask(
                        task_id=schedule_config["task_id"],
                        schedule_type=schedule_config["schedule_type"],
                        schedule_time=schedule_config["schedule_time"],
                        days=schedule_config.get("days", []),
                        enabled=schedule_config.get("enabled", True)
                    )
                    self.scheduled_tasks[schedule_id] = scheduled_task
                    self._setup_schedule(scheduled_task)
        
        except Exception:
            pass  # Use defaults if config loading fails
    
    def register_task_complete_callback(self, callback: Callable[[AutomationResult], None]):
        """Register callback for task completion"""
        self.task_complete_callbacks.append(callback)
    
    def get_profile_tasks(self, profile: OptimizationProfile) -> List[AutomationTask]:
        """Get all tasks for a specific profile"""
        return [task for task in self.tasks.values() if task.profile == profile]
    
    def get_task_statistics(self) -> Dict[str, Any]:
        """Get automation statistics"""
        total_tasks = len(self.tasks)
        enabled_tasks = sum(1 for task in self.tasks.values() if task.enabled)
        total_successes = sum(task.success_count for task in self.tasks.values())
        total_errors = sum(task.error_count for task in self.tasks.values())
        
        recent_results = [r for r in self.results_history if r.timestamp > datetime.now() - timedelta(days=7)]
        recent_successes = sum(1 for r in recent_results if r.success)
        
        return {
            "total_tasks": total_tasks,
            "enabled_tasks": enabled_tasks,
            "total_successes": total_successes,
            "total_errors": total_errors,
            "recent_successes": recent_successes,
            "recent_total": len(recent_results),
            "success_rate": (recent_successes / len(recent_results) * 100) if recent_results else 0
        }

# === Smart Automation Widget ===
class SmartAutomationWidget:
    """Tkinter widget for controlling smart automation"""
    
    def __init__(self, parent, automation: SmartAutomation):
        self.parent = parent
        self.automation = automation
        self.setup_ui()
        
        # Register for task completion updates
        self.automation.register_task_complete_callback(self.on_task_complete)
    
    def setup_ui(self):
        """Setup the automation control UI"""
        # Main frame
        self.main_frame = ttk.LabelFrame(self.parent, text="🤖 Smart Automation", padding=15)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Quick profiles section
        profiles_frame = ttk.LabelFrame(self.main_frame, text="Quick Optimization Profiles", padding=10)
        profiles_frame.pack(fill="x", pady=10)
        
        # Profile buttons
        button_frame = ttk.Frame(profiles_frame)
        button_frame.pack(fill="x")
        
        profiles = [
            ("🎮 Gaming", OptimizationProfile.GAMING, "success"),
            ("💼 Work", OptimizationProfile.WORK, "info"),
            ("🔒 Privacy", OptimizationProfile.PRIVACY, "warning"),
            ("⚡ Performance", OptimizationProfile.PERFORMANCE, "primary"),
            ("🔧 Maintenance", OptimizationProfile.MAINTENANCE, "secondary")
        ]
        
        for i, (name, profile, style) in enumerate(profiles):
            btn = tb.Button(
                button_frame,
                text=name,
                bootstyle=style,
                width=15,
                command=lambda p=profile: self.automation.apply_profile(p)
            )
            btn.grid(row=0, column=i, padx=5, pady=5, sticky="ew")
        
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)
        button_frame.grid_columnconfigure(3, weight=1)
        button_frame.grid_columnconfigure(4, weight=1)
        
        # Advanced controls section
        advanced_frame = ttk.LabelFrame(self.main_frame, text="Advanced Automation", padding=10)
        advanced_frame.pack(fill="x", pady=10)
        
        # Task scheduling
        schedule_frame = ttk.Frame(advanced_frame)
        schedule_frame.pack(fill="x", pady=5)
        
        ttk.Label(schedule_frame, text="Schedule Task:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=5)
        
        self.task_var = tk.StringVar()
        task_combo = ttk.Combobox(schedule_frame, textvariable=self.task_var, width=20, state="readonly")
        task_combo['values'] = [task.name for task in self.automation.tasks.values()]
        task_combo.grid(row=0, column=1, padx=5)
        
        self.schedule_type_var = tk.StringVar(value="daily")
        schedule_combo = ttk.Combobox(schedule_frame, textvariable=self.schedule_type_var, width=10, state="readonly")
        schedule_combo['values'] = ['daily', 'weekly', 'interval']
        schedule_combo.grid(row=0, column=2, padx=5)
        
        self.schedule_time_var = tk.StringVar(value="14:30")
        time_entry = ttk.Entry(schedule_frame, textvariable=self.schedule_time_var, width=10)
        time_entry.grid(row=0, column=3, padx=5)
        
        schedule_btn = tb.Button(schedule_frame, text="Add Schedule", bootstyle="info",
                               command=self.add_schedule)
        schedule_btn.grid(row=0, column=4, padx=5)
        
        # Scheduled tasks list
        scheduled_tasks_frame = ttk.LabelFrame(advanced_frame, text="Scheduled Tasks", padding=5)
        scheduled_tasks_frame.pack(fill="x", pady=5)
        
        columns = ("Task", "Schedule", "Status")
        self.scheduled_tree = ttk.Treeview(scheduled_tasks_frame, columns=columns, show="headings", height=4)
        
        for col in columns:
            self.scheduled_tree.heading(col, text=col)
            self.scheduled_tree.column(col, width=150)
        
        scheduled_scrollbar = ttk.Scrollbar(scheduled_tasks_frame, orient="vertical", command=self.scheduled_tree.yview)
        self.scheduled_tree.configure(yscrollcommand=scheduled_scrollbar.set)
        
        self.scheduled_tree.pack(side="left", fill="both", expand=True)
        scheduled_scrollbar.pack(side="right", fill="y")
        
        # Statistics section
        stats_frame = ttk.LabelFrame(self.main_frame, text="Automation Statistics", padding=10)
        stats_frame.pack(fill="x", pady=10)
        
        self.stats_label = ttk.Label(stats_frame, text="Loading statistics...", font=("Segoe UI", 10))
        self.stats_label.pack()
        
        # Task status section
        status_frame = ttk.LabelFrame(self.main_frame, text="Recent Task Activity", padding=10)
        status_frame.pack(fill="both", expand=True, pady=10)
        
        self.status_text = tk.Text(status_frame, height=8, wrap=tk.WORD, font=("Consolas", 9))
        status_scrollbar = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=status_scrollbar.set)
        
        self.status_text.pack(side="left", fill="both", expand=True)
        status_scrollbar.pack(side="right", fill="y")
        
        # Update displays
        self.update_statistics()
        self.update_scheduled_tasks()
        self.update_recent_activity()
        
        # Schedule updates
        self.parent.after(5000, self.update_statistics)
        self.parent.after(10000, self.update_scheduled_tasks)
    
    def add_schedule(self):
        """Add a new scheduled task"""
        task_name = self.task_var.get()
        schedule_type = self.schedule_type_var.get()
        schedule_time = self.schedule_time_var.get()
        
        if not task_name:
            messagebox.showwarning("Warning", "Please select a task to schedule.")
            return
        
        # Find task ID
        task_id = None
        for task in self.automation.tasks.values():
            if task.name == task_name:
                task_id = task.id
                break
        
        if task_id and self.automation.schedule_task(task_id, schedule_type, schedule_time):
            messagebox.showinfo("Success", f"Task '{task_name}' scheduled successfully!")
            self.update_scheduled_tasks()
        else:
            messagebox.showerror("Error", "Failed to schedule task.")
    
    def update_statistics(self):
        """Update automation statistics display"""
        try:
            stats = self.automation.get_task_statistics()
            stats_text = (
                f"Tasks: {stats['enabled_tasks']}/{stats['total_tasks']} active | "
                f"Success Rate: {stats['success_rate']:.1f}% | "
                f"Recent Runs: {stats['recent_successes']}/{stats['recent_total']} | "
                f"Total Successes: {stats['total_successes']}"
            )
            self.stats_label.configure(text=stats_text)
        except Exception:
            self.stats_label.configure(text="Statistics unavailable")
        
        # Schedule next update
        self.parent.after(10000, self.update_statistics)
    
    def update_scheduled_tasks(self):
        """Update scheduled tasks display"""
        # Clear existing items
        for item in self.scheduled_tree.get_children():
            self.scheduled_tree.delete(item)
        
        # Add scheduled tasks
        for schedule_id, scheduled_task in self.automation.scheduled_tasks.items():
            task = self.automation.tasks.get(scheduled_task.task_id)
            if task:
                status = "Active" if scheduled_task.enabled else "Disabled"
                schedule_info = f"{scheduled_task.schedule_type} at {scheduled_task.schedule_time}"
                self.scheduled_tree.insert("", "end", values=(task.name, schedule_info, status))
    
    def update_recent_activity(self):
        """Update recent activity display"""
        self.status_text.delete(1.0, tk.END)
        
        recent_results = sorted(self.automation.results_history, 
                              key=lambda x: x.timestamp, reverse=True)[:10]
        
        for result in recent_results:
            task = self.automation.tasks.get(result.task_id)
            if task:
                status = "✅" if result.success else "❌"
                timestamp = result.timestamp.strftime("%H:%M:%S")
                self.status_text.insert(tk.END, f"{timestamp} {status} {task.name}: {result.message}\n")
        
        # Schedule next update
        self.parent.after(30000, self.update_recent_activity)
    
    def on_task_complete(self, result: AutomationResult):
        """Handle task completion"""
        # Update displays when tasks complete
        self.parent.after(0, self.update_statistics)
        self.parent.after(0, self.update_recent_activity)

# === Admin Check & Elevation ===
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart script as admin using ShellExecuteW"""
    script = sys.argv[0]
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
    sys.exit(0)

if not is_admin():
    run_as_admin()

# === Enhanced Animation Handler ===
class SmoothAnimationHandler:
    def __init__(self, widget):
        self.widget = widget
        self.is_running = False
        self.animations = {
            'scanning': ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            'cleaning': ["🧹", "🧽", "🚮", "✨", "🧹", "🧽", "🚮", "✨"],
            'analyzing': ["🔍", "🔎", "🔬", "📊", "🔍", "🔎", "🔬", "📊"],
            'processing': ["⚙️", "⚡", "🔧", "🛠️", "⚙️", "⚡", "🔧", "🛠️"],
            'virus_scan': ["🛡️", "🔍", "🦠", "⚠️", "🛡️", "🔍", "🦠", "⚠️"]
        }
        self.current_frame = 0
        self.current_animation = 'scanning'

    def start(self, animation_type: str = 'scanning', message: str = "Processing"):
        if animation_type in self.animations:
            self.current_animation = animation_type
        self.is_running = True
        self.current_frame = 0
        self._animate(message)

    def _animate(self, message: str):
        if self.is_running:
            try:
                frames = self.animations[self.current_animation]
                self.widget.configure(text=f"{message} {frames[self.current_frame]}")
                self.current_frame = (self.current_frame + 1) % len(frames)
                self.widget.after(120, lambda: self._animate(message))
            except tk.TclError:
                self.stop()

    def stop(self):
        self.is_running = False
        try:
            self.widget.configure(text="Ready")
        except tk.TclError:
            pass

# === Enhanced Progress Handler ===
class EnhancedProgressHandler:
    def __init__(self, progressbar: ttk.Progressbar, status_label: ttk.Label = None, 
                 detail_label: ttk.Label = None):
        self.progressbar = progressbar
        self.status_label = status_label
        self.detail_label = detail_label
        self.is_cancelled = False
        self.start_time = time.time()

    def update(self, current: int, total: int, message: str = "", detail: str = ""):
        try:
            progress = (current / total * 100) if total > 0 else 0
            self.progressbar.configure(value=progress)
            
            elapsed = time.time() - self.start_time
            if current > 0 and total > current:
                eta = (elapsed / current) * (total - current)
                eta_str = f" (ETA: {int(eta)}s)"
            else:
                eta_str = ""
            
            if self.status_label:
                self.status_label.configure(text=f"{message} ({current}/{total}){eta_str}")
            
            if self.detail_label and detail:
                # Truncate long paths for display
                if len(detail) > 60:
                    detail = "..." + detail[-57:]
                self.detail_label.configure(text=detail)
            
            self.progressbar.update_idletasks()
        except tk.TclError:
            pass

    def set_indeterminate(self, active: bool = True):
        if active:
            self.progressbar.configure(mode='indeterminate')
            self.progressbar.start()
        else:
            self.progressbar.stop()
            self.progressbar.configure(mode='determinate', value=0)

    def reset(self):
        self.is_cancelled = False
        self.start_time = time.time()
        self.progressbar.configure(value=0)
        if self.status_label:
            self.status_label.configure(text="Ready")
        if self.detail_label:
            self.detail_label.configure(text="")

# === Virus Scanner Engine ===
class VirusScanner:
    def __init__(self, logger=None):
        self.logger = logger
        self.is_scanning = False
        self.current_scan_id = None
        self.mpcmdrun_path = self._find_mpcmdrun()
        
    def _find_mpcmdrun(self) -> Optional[Path]:
        """Find the Windows Defender command line utility"""
        possible_paths = [
            Path("C:/Program Files/Windows Defender/MpCmdRun.exe"),
            Path("C:/Program Files (x86)/Windows Defender/MpCmdRun.exe"),
            Path(os.getenv("ProgramFiles", "")) / "Windows Defender" / "MpCmdRun.exe",
            Path(os.getenv("ProgramFiles(x86)", "")) / "Windows Defender" / "MpCmdRun.exe",
        ]
        
        for path in possible_paths:
            if path.exists():
                return path
        return None
    
    def is_available(self) -> bool:
        """Check if Windows Defender is available"""
        return self.mpcmdrun_path is not None
    
    def quick_scan(self, progress_callback: Optional[Callable] = None) -> List[VirusScanResult]:
        """Perform a quick system scan"""
        return self._run_scan("-Scan -ScanType 1", "Quick scan", progress_callback)
    
    def full_scan(self, progress_callback: Optional[Callable] = None) -> List[VirusScanResult]:
        """Perform a full system scan"""
        return self._run_scan("-Scan -ScanType 2", "Full scan", progress_callback)
    
    def custom_scan(self, path: str, progress_callback: Optional[Callable] = None) -> List[VirusScanResult]:
        """Scan a specific file or directory"""
        return self._run_scan(f'-Scan -ScanType 3 -File "{path}"', f"Custom scan: {path}", progress_callback)
    
    def _run_scan(self, args: str, scan_type: str, progress_callback: Optional[Callable] = None) -> List[VirusScanResult]:
        """Execute a scan command and parse results"""
        if not self.is_available():
            if self.logger:
                self.logger.log("Windows Defender not found. Virus scanning unavailable.", LogLevel.ERROR)
            return []
        
        self.is_scanning = True
        self.current_scan_id = str(uuid.uuid4())[:8]
        
        if self.logger:
            self.logger.log(f"Starting {scan_type} (ID: {self.current_scan_id})", LogLevel.SECURITY)
        
        try:
            # Run the scan command
            cmd = f'"{self.mpcmdrun_path}" {args}'
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            
            # Monitor progress
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                output = line.decode('utf-8', errors='ignore').strip()
                output_lines.append(output)
                
                # Parse progress if available
                if progress_callback and "%" in output:
                    try:
                        percent = int(re.search(r'(\d+)%', output).group(1))
                        progress_callback(percent, 100, f"{scan_type} in progress", f"Scanning... {percent}%")
                    except:
                        pass
                
                if self.logger and "found" in output.lower():
                    self.logger.log(f"Scan update: {output}", LogLevel.SECURITY)
            
            process.wait()
            
            # Get detailed results
            results = self._get_scan_results()
            
            if self.logger:
                threats_found = len([r for r in results if r.threat_name])
                if threats_found > 0:
                    self.logger.log(f"Scan completed: {threats_found} threats found", LogLevel.SECURITY)
                else:
                    self.logger.log(f"Scan completed: No threats found", LogLevel.SUCCESS)
            
            return results
            
        except Exception as e:
            if self.logger:
                self.logger.log(f"Virus scan failed: {str(e)}", LogLevel.ERROR)
            return []
        finally:
            self.is_scanning = False
            self.current_scan_id = None
    
    def _get_scan_results(self) -> List[VirusScanResult]:
        """Get the latest scan results from Windows Defender"""
        try:
            # Create a temporary file for results
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                temp_file = f.name
            
            # Export results to XML
            cmd = f'"{self.mpcmdrun_path}" -GetFiles -ScanID 0 -Path "{temp_file}"'
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            
            # Parse XML results
            if os.path.exists(temp_file):
                tree = ET.parse(temp_file)
                root = tree.getroot()
                
                results = []
                for item in root.findall('.//Threat'):
                    result = VirusScanResult(
                        file_path=item.find('Path').text if item.find('Path') is not None else "Unknown",
                        threat_name=item.find('Name').text if item.find('Name') is not None else "Unknown",
                        severity=item.find('Severity').text if item.find('Severity') is not None else "Unknown",
                        action_taken=item.find('Action').text if item.find('Action') is not None else "None"
                    )
                    results.append(result)
                
                os.unlink(temp_file)
                return results
                
        except Exception as e:
            if self.logger:
                self.logger.log(f"Failed to get scan results: {str(e)}", LogLevel.ERROR)
        
        return []
    
    def get_defender_status(self) -> Dict[str, str]:
        """Get Windows Defender status information"""
        try:
            # Use PowerShell to get Defender status
            ps_script = """
            Get-MpComputerStatus | Select-Object AntivirusEnabled, AMServiceEnabled, 
            AntivirusSignatureLastUpdated, AntispywareEnabled, BehaviorMonitorEnabled, 
            IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, 
            RealTimeProtectionEnabled | ConvertTo-Json
            """
            
            result = subprocess.run([
                "powershell", "-Command", ps_script
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": "Failed to get Defender status"}
                
        except Exception as e:
            return {"error": str(e)}

# === Deep Scan Engine ===
class DeepScanEngine:
    def __init__(self, logger=None):
        self.logger = logger
        self.common_program_locations = [
            Path(os.getenv("ProgramFiles", "")),
            Path(os.getenv("ProgramFiles(x86)", "")),
        ]
        self.user_data_locations = [
            Path(os.getenv("LOCALAPPDATA", "")),
            Path(os.getenv("APPDATA", "")),
            Path(os.getenv("USERPROFILE", "")) / "Documents",
            Path(os.getenv("PUBLIC", "")) / "Documents",
        ]
        self.system_locations = [
            Path("C:\\Windows\\System32"),
            Path("C:\\Windows\\SysWOW64"),
        ]

    def deep_scan_leftovers(self, program_name: str, install_location: str = "", 
                           progress_callback: Optional[Callable] = None) -> DeepScanResult:
        """Perform deep scan for leftover files, folders, and registry entries"""
        start_time = time.time()
        leftover_items = []
        
        # Clean program name for searching
        clean_name = self._clean_program_name(program_name)
        search_terms = self._generate_search_terms(program_name, clean_name)
        
        total_steps = 7
        current_step = 0
        
        try:
            # Step 1: Scan Program Files
            if progress_callback:
                progress_callback(current_step, total_steps, "Scanning Program Files", "")
            leftover_items.extend(self._scan_program_files(search_terms, install_location))
            current_step += 1
            
            # Step 2: Scan User Data
            if progress_callback:
                progress_callback(current_step, total_steps, "Scanning User Data", "")
            leftover_items.extend(self._scan_user_data(search_terms))
            current_step += 1
            
            # Step 3: Scan Registry
            if progress_callback:
                progress_callback(current_step, total_steps, "Scanning Registry", "")
            leftover_items.extend(self._scan_registry(search_terms))
            current_step += 1
            
            # Step 4: Scan Shortcuts
            if progress_callback:
                progress_callback(current_step, total_steps, "Scanning Shortcuts", "")
            leftover_items.extend(self._scan_shortcuts(search_terms))
            current_step += 1
            
            # Step 5: Scan Temporary Files
            if progress_callback:
                progress_callback(current_step, total_steps, "Scanning Temp Files", "")
            leftover_items.extend(self._scan_temp_files(search_terms))
            current_step += 1
            
            # Step 6: Scan System Files
            if progress_callback:
                progress_callback(current_step, total_steps, "Scanning System Files", "")
            leftover_items.extend(self._scan_system_files(search_terms))
            current_step += 1
            
            # Step 7: Calculate confidence scores
            if progress_callback:
                progress_callback(current_step, total_steps, "Analyzing Results", "")
            self._calculate_confidence_scores(leftover_items, search_terms)
            current_step += 1
            
        except Exception as e:
            if self.logger:
                self.logger.log(f"Deep scan error: {str(e)}", LogLevel.ERROR)
        
        total_size = sum(item.size for item in leftover_items)
        scan_time = time.time() - start_time
        
        return DeepScanResult(program_name, leftover_items, total_size, scan_time)

    def _clean_program_name(self, name: str) -> str:
        """Clean program name for better searching"""
        # Remove version numbers, common suffixes, and special characters
        clean = re.sub(r'\s*\d+\.\d+.*$', '', name)  # Remove version numbers
        clean = re.sub(r'\s*(x64|x86|64-bit|32-bit).*$', '', clean, flags=re.IGNORECASE)
        clean = re.sub (r'\s*(Professional|Pro|Enterprise|Standard|Home|Personal).*$', '', clean, flags=re.IGNORECASE)
        clean = re.sub(r'[^\w\s]', '', clean)  # Remove special characters
        return clean.strip()

    def _generate_search_terms(self, original_name: str, clean_name: str) -> Set[str]:
        """Generate various search terms for the program"""
        terms = {original_name.lower(), clean_name.lower()}
        
        # Add words from the program name
        for word in clean_name.split():
            if len(word) > 2:  # Ignore short words
                terms.add(word.lower())
        
        # Add company name if detectable
        company_patterns = [
            r'(\w+)\s+(?:Corporation|Corp|Inc|LLC|Ltd)',
            r'(\w+)\s+(?:Software|Systems|Technologies)'
        ]
        for pattern in company_patterns:
            match = re.search(pattern, original_name, re.IGNORECASE)
            if match:
                terms.add(match.group(1).lower())
        
        return terms

    def _scan_program_files(self, search_terms: Set[str], install_location: str = "") -> List[LeftoverItem]:
        """Scan Program Files directories for leftovers"""
        leftovers = []
        
        # First check the specific install location if provided
        if install_location and Path(install_location).exists():
            try:
                install_path = Path(install_location)
                if install_path.is_dir():
                    leftovers.append(LeftoverItem(
                        install_path, "folder", 
                        self._get_folder_size(install_path),
                        "program_files", "High"
                    ))
            except (PermissionError, OSError):
                pass
        
        # Scan common program directories
        for base_dir in self.common_program_locations:
            if not base_dir.exists():
                continue
                
            try:
                for item in base_dir.iterdir():
                    if item.is_dir():
                        item_name = item.name.lower()
                        if any(term in item_name for term in search_terms):
                            size = self._get_folder_size(item)
                            leftovers.append(LeftoverItem(
                                item, "folder", size, "program_files", "High"
                            ))
            except (PermissionError, OSError):
                continue
                
        return leftovers

    def _scan_user_data(self, search_terms: Set[str]) -> List[LeftoverItem]:
        """Scan user data directories for leftovers"""
        leftovers = []
        
        for base_dir in self.user_data_locations:
            if not base_dir.exists():
                continue
                
            try:
                for item in base_dir.iterdir():
                    item_name = item.name.lower()
                    if any(term in item_name for term in search_terms):
                        if item.is_dir():
                            size = self._get_folder_size(item)
                            leftovers.append(LeftoverItem(
                                item, "folder", size, "appdata", "Medium"
                            ))
                        else:
                            size = item.stat().st_size
                            leftovers.append(LeftoverItem(
                                item, "file", size, "appdata", "Medium"
                            ))
            except (PermissionError, OSError):
                continue
                
        return leftovers

    def _scan_registry(self, search_terms: Set[str]) -> List[LeftoverItem]:
        """Scan Windows Registry for leftover entries"""
        leftovers = []
        
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node"),
        ]
        
        for hive, path in registry_paths:
            try:
                self._scan_registry_key(hive, path, search_terms, leftovers)
            except (PermissionError, OSError):
                continue
                
        return leftovers

    def _scan_registry_key(self, hive, path: str, search_terms: Set[str], 
                          leftovers: List[LeftoverItem], depth: int = 0):
        """Recursively scan a registry key"""
        if depth > 3:  # Limit recursion depth
            return
            
        try:
            key = winreg.OpenKey(hive, path)
            num_subkeys = winreg.QueryInfoKey(key)[0]
            
            for i in range(min(num_subkeys, 100)):  # Limit number of subkeys to scan
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    if any(term in subkey_name.lower() for term in search_terms):
                        full_path = f"{path}\\{subkey_name}"
                        leftovers.append(LeftoverItem(
                            Path(full_path), "registry", 0, "registry", "Medium"
                        ))
                    
                    # Recurse into subkey if it might contain relevant entries
                    if depth < 2 and len(subkey_name) > 3:
                        subkey_path = f"{path}\\{subkey_name}"
                        self._scan_registry_key(hive, subkey_path, search_terms, 
                                              leftovers, depth + 1)
                        
                except (OSError, PermissionError):
                    continue
                    
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError, OSError):
            pass

    def _scan_shortcuts(self, search_terms: Set[str]) -> List[LeftoverItem]:
        """Scan for leftover shortcuts"""
        leftovers = []
        
        shortcut_locations = [
            Path(os.getenv("PUBLIC", "")) / "Desktop",
            Path(os.getenv("USERPROFILE", "")) / "Desktop",
            Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
            Path(os.getenv("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
        ]
        
        for location in shortcut_locations:
            if not location.exists():
                continue
                
            try:
                for item in location.rglob("*.lnk"):
                    item_name = item.name.lower()
                    if any(term in item_name for term in search_terms):
                        leftovers.append(LeftoverItem(
                            item, "file", item.stat().st_size, "shortcuts", "High"
                        ))
            except (PermissionError, OSError):
                continue
                
        return leftovers

    def _scan_temp_files(self, search_terms: Set[str]) -> List[LeftoverItem]:
        """Scan temporary directories for leftovers"""
        leftovers = []
        
        temp_locations = [
            Path(os.getenv("TEMP", "")),
            Path("C:\\Windows\\Temp"),
            Path(os.getenv("LOCALAPPDATA", "")) / "Temp",
        ]
        
        for temp_dir in temp_locations:
            if not temp_dir.exists():
                continue
                
            try:
                for item in temp_dir.iterdir():
                    item_name = item.name.lower()
                    if any(term in item_name for term in search_terms):
                        if item.is_dir():
                            size = self._get_folder_size(item)
                            leftovers.append(LeftoverItem(
                                item, "folder", size, "temp", "Low"
                            ))
                        else:
                            size = item.stat().st_size
                            leftovers.append(LeftoverItem(
                                item, "file", size, "temp", "Low"
                            ))
            except (PermissionError, OSError):
                continue
                
        return leftovers

    def _scan_system_files(self, search_terms: Set[str]) -> List[LeftoverItem]:
        """Scan system directories for leftover files (DLLs, etc.)"""
        leftovers = []
        
        for sys_dir in self.system_locations:
            if not sys_dir.exists():
                continue
                
            try:
                for item in sys_dir.glob("*.dll"):
                    item_name = item.name.lower()
                    if any(term in item_name for term in search_terms):
                        leftovers.append(LeftoverItem(
                            item, "file", item.stat().st_size, "system", "Low"
                        ))
            except (PermissionError, OSError):
                continue
                
        return leftovers

    def _get_folder_size(self, folder_path: Path) -> int:
        """Calculate total size of a folder"""
        total_size = 0
        try:
            for item in folder_path.rglob("*"):
                if item.is_file():
                    try:
                        total_size += item.stat().st_size
                    except (OSError, FileNotFoundError):
                        continue
        except (PermissionError, OSError):
            pass
        return total_size

    def _calculate_confidence_scores(self, leftovers: List[LeftoverItem], search_terms: Set[str]):
        """Calculate confidence scores based on various factors"""
        for item in leftovers:
            # Start with base confidence
            confidence_score = 0.5
            
            # Increase confidence based on category
            category_weights = {
                "program_files": 0.4,
                "shortcuts": 0.3,
                "appdata": 0.2,
                "registry": 0.1,
                "temp": 0.05,
                "system": 0.05
            }
            confidence_score += category_weights.get(item.category, 0)
            
            # Increase confidence based on exact matches
            item_name = item.path.name.lower()
            exact_matches = sum(1 for term in search_terms if term == item_name)
            confidence_score += exact_matches * 0.2
            
            # Increase confidence based on partial matches
            partial_matches = sum(1 for term in search_terms if term in item_name)
            confidence_score += partial_matches * 0.1
            
            # Assign final confidence level
            if confidence_score >= 0.8:
                item.confidence = "High"
            elif confidence_score >= 0.5:
                item.confidence = "Medium"
            else:
                item.confidence = "Low"

# === Enhanced Async Logger ===
class AsyncLogger:
    def __init__(self, text_widget: tk.Text):
        self.log_widget = text_widget
        self.log_queue = queue.Queue()
        self.is_running = True
        self._setup_log_colors()
        self._start_log_processor()

    def _setup_log_colors(self):
        """Setup enhanced color scheme for different log levels"""
        colors = {
            LogLevel.INFO.value: ("#2C3E50", "#ECF0F1"),
            LogLevel.SUCCESS.value: ("#27AE60", "#D5EFDE"), 
            LogLevel.WARNING.value: ("#F39C12", "#FEF3E2"),
            LogLevel.ERROR.value: ("#E74C3C", "#FADBD8"),
            LogLevel.SCAN.value: ("#3498DB", "#D6EBF5"),
            LogLevel.SECURITY.value: ("#9B59B6", "#E8DAEF")
        }
        
        for level, (fg, bg) in colors.items():
            self.log_widget.tag_configure(level, foreground=fg, background=bg)

    def _start_log_processor(self):
        def process_logs():
            while self.is_running:
                try:
                    log_msg = self.log_queue.get(timeout=0.1)
                    self._update_log_widget(log_msg)
                except queue.Empty:
                    continue
                except tk.TclError:
                    break
        
        threading.Thread(target=process_logs, daemon=True).start()

    def _update_log_widget(self, log_msg: LogMessage):
        try:
            self.log_widget.config(state=tk.NORMAL)
            
            # Add log entry with enhanced formatting
            timestamp_tag = f"{log_msg.level.value}_timestamp"
            self.log_widget.tag_configure(timestamp_tag, foreground="gray", font=("Consolas", 9))
            
            self.log_widget.insert(tk.END, f"[{log_msg.timestamp}] ", timestamp_tag)
            self.log_widget.insert(tk.END, f"[{log_msg.level.value}] ", log_msg.level.value)
            self.log_widget.insert(tk.END, f"{log_msg.message}\n")
            
            # Limit log size
            lines = int(self.log_widget.index(tk.END).split('.')[0])
            if lines > 1000:
                self.log_widget.delete('1.0', '100.0')
            
            self.log_widget.see(tk.END)
            self.log_widget.config(state=tk.DISABLED)
        except tk.TclError:
            pass

    def log(self, message: str, level: LogLevel = LogLevel.INFO):
        timestamp = time.strftime("%H:%M:%S")
        log_msg = LogMessage(message, level, timestamp)
        self.log_queue.put(log_msg)

    def stop(self):
        self.is_running = False

# === Enhanced Registry Helper ===
class EnhancedRegistryHelper:
    @staticmethod
    def get_installed_programs_async(progress_callback: Optional[Callable] = None) -> List[ProgramInfo]:
        programs = []
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        
        total_keys = len(keys)
        for idx, (hive, path) in enumerate(keys):
            if progress_callback:
                progress_callback(idx, total_keys, f"Scanning registry", path)
                
            try:
                reg_key = winreg.OpenKey(hive, path)
                num_subkeys = winreg.QueryInfoKey(reg_key)[0]
                
                for i in range(num_subkeys):
                    if progress_callback and i % 5 == 0:
                        progress_callback(idx, total_keys, f"Processing entries", f"{i}/{num_subkeys}")
                    
                    try:
                        subkey_name = winreg.EnumKey(reg_key, i)
                        subkey = winreg.OpenKey(reg_key, subkey_name)
                        
                        # Get program information
                        program_info = EnhancedRegistryHelper._extract_program_info(subkey)
                        if program_info:
                            programs.append(program_info)
                            
                        winreg.CloseKey(subkey)
                    except (OSError, PermissionError):
                        continue
                        
                winreg.CloseKey(reg_key)
            except (FileNotFoundError, PermissionError):
                continue
                
        return sorted(programs, key=lambda x: x.name.lower())

    @staticmethod
    def _extract_program_info(subkey) -> Optional[ProgramInfo]:
        """Extract detailed program information from registry"""
        try:
            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
            if not display_name:
                return None
                
            # Get additional information
            uninstall_str = ""
            install_location = ""
            publisher = ""
            version = ""
            size = ""
            install_date = ""
            
            try:
                uninstall_str = winreg.QueryValueEx(subkey, "UninstallString")[0]
            except FileNotFoundError:
                pass
                
            try:
                install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
            except FileNotFoundError:
                pass
                
            try:
                publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
            except FileNotFoundError:
                pass
                
            try:
                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
            except FileNotFoundError:
                pass
                
            try:
                size_kb = int(winreg.QueryValueEx(subkey, "EstimatedSize")[0])
                size = f"{size_kb / 1024:.1f} MB"
            except (FileNotFoundError, ValueError):
                pass
                
            try:
                install_date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                if len(install_date) == 8:  # Format: YYYYMMDD
                    install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"
            except FileNotFoundError:
                pass
            
            return ProgramInfo(display_name, uninstall_str, install_location, 
                             publisher, version, size, install_date)
                             
        except FileNotFoundError:
            return None

    @staticmethod
    def get_startup_programs_async(progress_callback: Optional[Callable] = None) -> List[StartupItem]:
        items = []
        paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        for idx, (hive, path) in enumerate(paths):
            if progress_callback:
                progress_callback(idx, len(paths), "Scanning startup entries", path)
                
            try:
                reg_key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(reg_key, i)
                        items.append(StartupItem(name, val, hive, path))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(reg_key)
            except FileNotFoundError:
                continue
                
        return items

    @staticmethod
    def remove_startup_entry(item: StartupItem) -> bool:
        try:
            reg_key = winreg.OpenKey(item.hive, item.registry_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(reg_key, item.name)
            winreg.CloseKey(reg_key)
            return True
        except Exception:
            return False

# === Enhanced Async Junk Cleaner ===
class AsyncJunkCleaner:
    @staticmethod
    def scan_junk_files(progress_callback: Optional[Callable] = None) -> List[Path]:
        """Enhanced junk file scanning with better categorization"""
        junk_files = []
        
        # Define junk file locations and patterns
        junk_locations = {
            "Temporary Files": [
                (Path(os.getenv("TEMP", "")), ["*"]),
                (Path("C:\\Windows\\Temp"), ["*"]),
                (Path(os.getenv("LOCALAPPDATA", "")) / "Temp", ["*"]),
            ],
            "Browser Cache": [
                (Path(os.getenv("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Cache", ["*"]),
                (Path(os.getenv("LOCALAPPDATA", "")) / "Mozilla" / "Firefox" / "Profiles", ["*.default*", "cache2"]),
                (Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache", ["*"]),
            ],
            "Windows Cache": [
                (Path("C:\\Windows\\SoftwareDistribution\\Download"), ["*"]),
                (Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Explorer", ["thumbcache*.db"]),
                (Path("C:\\Windows\\Prefetch"), ["*.pf"]),
            ],
            "System Logs": [
                (Path("C:\\Windows\\Logs"), ["*.log", "*.etl"]),
                (Path(os.getenv("LOCALAPPDATA", "")) / "CrashDumps", ["*.dmp"]),
            ],
            "Recycle Bin": [
                (Path("C:\\$Recycle.Bin"), ["*"]),
            ]
        }
        
        total_locations = sum(len(locations) for locations in junk_locations.values())
        current_location = 0
        
        for category, locations in junk_locations.items():
            for base_path, patterns in locations:
                current_location += 1
                
                if progress_callback:
                    progress_callback(current_location, total_locations, 
                                    f"Scanning {category}", str(base_path))
                
                if not base_path.exists():
                    continue
                
                try:
                    for pattern in patterns:
                        if pattern == "*":
                            # Scan all files in directory
                            for item in base_path.rglob("*"):
                                if item.is_file() and AsyncJunkCleaner._is_safe_to_delete(item):
                                    junk_files.append(item)
                        else:
                            # Scan specific patterns
                            for item in base_path.rglob(pattern):
                                if item.is_file() and AsyncJunkCleaner._is_safe_to_delete(item):
                                    junk_files.append(item)
                except (PermissionError, OSError):
                    continue
        
        # Remove duplicates and sort
        junk_files = list(set(junk_files))
        junk_files.sort(key=lambda x: x.stat().st_size, reverse=True)
        
        return junk_files

    @staticmethod
    def clean_junk_files(files: List[Path], progress_callback: Optional[Callable] = None) -> Tuple[int, int]:
        """Clean junk files with progress tracking"""
        cleaned_count = 0
        total_freed = 0
        
        for i, file_path in enumerate(files):
            if progress_callback:
                progress_callback(i, len(files), "Cleaning files", str(file_path))
            
            try:
                if file_path.exists():
                    file_size = file_path.stat().st_size
                    if file_path.is_dir():
                        shutil.rmtree(file_path, ignore_errors=True)
                    else:
                        file_path.unlink()
                    cleaned_count += 1
                    total_freed += file_size
            except (PermissionError, OSError, FileNotFoundError):
                continue
        
        return cleaned_count, total_freed

    @staticmethod
    def _is_safe_to_delete(file_path: Path) -> bool:
        """Check if a file is safe to delete"""
        # Don't delete system-critical files
        unsafe_extensions = {'.sys', '.dll', '.exe', '.ini'}
        if file_path.suffix.lower() in unsafe_extensions:
            return False
        
        # Don't delete files that are currently in use
        try:
            file_path.stat()
            return True
        except (PermissionError, FileNotFoundError):
            return False

# === Enhanced Main Application - Fixed & Optimized ===
class EnhancedPyUninstallXPro:
    def __init__(self):
        # Initialize main window with enhanced styling
        self.root = tb.Window(themename="cosmo")
        self.root.title("PyUninstallX Pro - Enhanced Deep Scan Edition")
        self.root.state("zoomed")
        self.root.configure(bg="#F8F9FA")
    
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
        # Enhanced thread management with optimal worker count
        self.thread_pool = ThreadPoolExecutor(
            max_workers=min(8, (os.cpu_count() or 4)),
            thread_name_prefix="PyUninstall"
        )
        self.active_operations = set()
    
        # Data storage with efficient structures
        self.programs_data: List[ProgramInfo] = []
        self.startup_data: List[StartupItem] = []
        self.last_scan_result: Optional[DeepScanResult] = None
    
        # UI state
        self.auto_scroll_var = tk.BooleanVar(value=True)
        self._filter_timer = None  # <-- ADD THIS LINE HERE
    
        # Pre-initialize logger placeholder to prevent AttributeError
        self.logger = None
        
        # Initialize components
        self.deep_scanner = DeepScanEngine()
        self.virus_scanner = VirusScanner()
        
        # Setup UI (creates self.log_text widget)
        self._setup_enhanced_ui()
        
        # NOW initialize logger with existing log_text widget
        self.logger = AsyncLogger(self.log_text)
        
        # Initialize smart automation with ready logger
        self.smart_automation = SmartAutomation(logger=self.logger)
        
        # Load initial data asynchronously
        self._load_initial_data()
        
        # Log startup
        self.safe_log("Enhanced PyUninstallX Pro started successfully", LogLevel.SUCCESS)
        
        # Start background optimization
        self._start_background_optimization()

    def safe_log(self, message: str, level: LogLevel = LogLevel.INFO):
        """Safe logging that handles None logger gracefully"""
        if self.logger:
            self.logger.log(message, level)
        else:
            print(f"[{level.name}] {message}")

    def _setup_enhanced_ui(self):
        """Setup enhanced UI with modern styling and smooth animations"""
        # Create main container with optimized layout
        main_container = ttk.Frame(self.root)
        main_container.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Enhanced notebook with custom styling
        style = ttk.Style()
        style.configure("Enhanced.TNotebook", tabposition='n')
        style.configure("Enhanced.TNotebook.Tab", 
                       padding=[20, 10], 
                       font=("Segoe UI", 11, "bold"))
        
        self.notebook = ttk.Notebook(main_container, style="Enhanced.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        # Initialize tabs dictionary
        self.tabs = {}
        
        # Optimized tab configuration with lazy loading support
        tab_configs = [
            ("Programs", "📦", self._setup_enhanced_programs_tab),
            ("Deep Scanner", "🔍", self._setup_deep_scanner_tab),
            ("Virus Scanner", "🛡️", self._setup_virus_scanner_tab),
            ("Smart Automation", "🤖", self._setup_smart_automation_tab),
            ("Startup", "⚡", self._setup_enhanced_startup_tab),
            ("Cleaner", "🧹", self._setup_enhanced_cleaner_tab),
            ("Tools", "🛠️", self._setup_enhanced_tools_tab),
            ("Settings", "⚙️", self._setup_enhanced_settings_tab),
            ("Logs", "📑", self._setup_enhanced_logs_tab)
        ]
        
        # Create tabs with optimized rendering
        for name, icon, setup_func in tab_configs:
            frame = ttk.Frame(self.notebook)
            self.tabs[name] = frame
            self.notebook.add(frame, text=f"{icon} {name}")
            
            # Setup tab content (logs tab MUST be created to get log_text widget)
            try:
                setup_func()
            except Exception as e:
                print(f"Error setting up {name} tab: {e}")

    def _load_initial_data(self):
        """Load initial data with enhanced progress tracking and parallel loading"""
        def load_programs():
            try:
                self.refresh_installed_programs()
            except Exception as e:
                self.safe_log(f"Error loading programs: {e}", LogLevel.ERROR)
        
        def load_startup():
            try:
                self.refresh_startup_programs()
            except Exception as e:
                self.safe_log(f"Error loading startup items: {e}", LogLevel.ERROR)
        
        # Submit parallel loading tasks
        self.thread_pool.submit(load_programs)
        self.thread_pool.submit(load_startup)

    def _start_background_optimization(self):
        """Start background optimization tasks"""
        def optimize():
            try:
                # Pre-cache common data
                self._cache_system_info()
                # Optimize memory usage
                import gc
                gc.collect()
            except Exception as e:
                self.safe_log(f"Background optimization error: {e}", LogLevel.WARNING)
        
        self.thread_pool.submit(optimize)

    def _cache_system_info(self):
        """Cache frequently accessed system information"""
        try:
            # Cache drive info
            self.cached_drives = [d.device for d in psutil.disk_partitions()]
            # Cache user directories
            self.cached_user_dirs = {
                'appdata': os.getenv('APPDATA'),
                'localappdata': os.getenv('LOCALAPPDATA'),
                'programdata': os.getenv('PROGRAMDATA'),
                'temp': os.getenv('TEMP')
            }
        except Exception as e:
            self.safe_log(f"Cache system info error: {e}", LogLevel.WARNING)

    def _setup_enhanced_programs_tab(self):
        """Enhanced programs tab with optimized rendering"""
        frame = self.tabs["Programs"]
        
        # Header with modern design
        header_frame = ttk.LabelFrame(frame, text="", padding=15)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(fill="x")
        
        ttk.Label(title_frame, text="📦 Installed Programs Manager", 
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        
        # Enhanced progress section
        progress_frame = ttk.Frame(title_frame)
        progress_frame.pack(side="right")
        
        self.programs_progress = ttk.Progressbar(
            progress_frame, length=250, mode="determinate", 
            style="success.Horizontal.TProgressbar"
        )
        self.programs_progress.pack(side="top", pady=2)
        
        self.programs_status = ttk.Label(progress_frame, text="Ready", 
                                        font=("Segoe UI", 10))
        self.programs_status.pack(side="top")
        
        self.programs_animation_label = ttk.Label(progress_frame, text="", 
                                                 font=("Segoe UI", 12))
        self.programs_animation_label.pack(side="top")
        self.programs_animator = SmoothAnimationHandler(self.programs_animation_label)
        
        # Enhanced search with filters
        search_frame = ttk.LabelFrame(frame, text="🔍 Search & Filter", padding=10)
        search_frame.pack(fill="x", padx=10, pady=5)
        
        search_row1 = ttk.Frame(search_frame)
        search_row1.pack(fill="x", pady=5)
        
        ttk.Label(search_row1, text="Search:", 
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 5))
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self._filter_programs_debounced)
        
        search_entry = ttk.Entry(search_row1, textvariable=self.search_var, 
                               width=30, font=("Segoe UI", 10))
        search_entry.pack(side="left", padx=(0, 15))
        
        ttk.Label(search_row1, text="Publisher:", 
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 5))
        
        self.publisher_filter = ttk.Combobox(search_row1, width=20, 
                                            font=("Segoe UI", 10))
        self.publisher_filter.pack(side="left")
        self.publisher_filter.bind('<<ComboboxSelected>>', 
                                  lambda e: self._filter_programs())
        
        # Enhanced program list with virtual scrolling support
        list_frame = ttk.LabelFrame(frame, text="Programs List", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Name", "Publisher", "Version", "Size", "Install Date", "Install Location")
        self.programs_tree = ttk.Treeview(
            list_frame, columns=columns, show="tree headings", 
            height=15, selectmode="extended"
        )
        
        # Configure columns with optimized widths
        self.programs_tree.heading("#0", text="", anchor="w")
        self.programs_tree.column("#0", width=0, stretch=False)
        
        column_widths = {
            "Name": 250, "Publisher": 150, "Version": 100, 
            "Size": 80, "Install Date": 100, "Install Location": 300
        }
        
        for col in columns:
            self.programs_tree.heading(col, text=col, anchor="w",
                                      command=lambda c=col: self._sort_programs(c))
            self.programs_tree.column(col, width=column_widths[col], anchor="w")
        
        # Optimized scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", 
                                   command=self.programs_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient="horizontal", 
                                   command=self.programs_tree.xview)
        
        self.programs_tree.configure(
            yscrollcommand=v_scrollbar.set, 
            xscrollcommand=h_scrollbar.set
        )
        
        self.programs_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Enhanced button panel with keyboard shortcuts
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)
        
        self.refresh_programs_btn = tb.Button(
            btn_frame, text="🔄 Refresh List (F5)", 
            bootstyle="info", width=20,
            command=self.refresh_installed_programs
        )
        self.refresh_programs_btn.pack(side="left", padx=8)
        
        self.uninstall_btn = tb.Button(
            btn_frame, text="🗑️ Smart Uninstall (Del)", 
            bootstyle="danger", width=22,
            command=self.smart_uninstall_program
        )
        self.uninstall_btn.pack(side="left", padx=8)
        
        self.quick_scan_btn = tb.Button(
            btn_frame, text="⚡ Quick Scan (Ctrl+Q)", 
            bootstyle="warning", width=20,
            command=self.quick_scan_leftovers
        )
        self.quick_scan_btn.pack(side="left", padx=8)
        
        # Bind keyboard shortcuts
        self.root.bind('<F5>', lambda e: self.refresh_installed_programs())
        self.root.bind('<Delete>', lambda e: self.smart_uninstall_program())
        self.root.bind('<Control-q>', lambda e: self.quick_scan_leftovers())
        
        # Context menu for right-click
        self._setup_programs_context_menu()

    def _setup_programs_context_menu(self):
        """Setup context menu for programs tree"""
        self.programs_context_menu = tk.Menu(self.root, tearoff=0)
        self.programs_context_menu.add_command(
            label="📋 Copy Name", 
            command=lambda: self._copy_program_info('name')
        )
        self.programs_context_menu.add_command(
            label="📂 Open Install Location", 
            command=self._open_install_location
        )
        self.programs_context_menu.add_separator()
        self.programs_context_menu.add_command(
            label="🗑️ Uninstall", 
            command=self.smart_uninstall_program
        )
        
        self.programs_tree.bind('<Button-3>', self._show_programs_context_menu)

    def _show_programs_context_menu(self, event):
        """Show context menu on right click"""
        try:
            self.programs_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.programs_context_menu.grab_release()

    def _copy_program_info(self, info_type: str):
        """Copy program information to clipboard"""
        try:
            selection = self.programs_tree.selection()
            if not selection:
                return
            
            item = self.programs_tree.item(selection[0])
            values = item['values']
            
            if info_type == 'name' and values:
                self.root.clipboard_clear()
                self.root.clipboard_append(values[0])
                self.safe_log(f"Copied '{values[0]}' to clipboard", LogLevel.INFO)
        except Exception as e:
            self.safe_log(f"Error copying info: {e}", LogLevel.ERROR)

    def _open_install_location(self):
        """Open program install location in explorer"""
        try:
            selection = self.programs_tree.selection()
            if not selection:
                return
            
            item = self.programs_tree.item(selection[0])
            values = item['values']
            
            if len(values) > 5 and values[5]:
                location = values[5]
                if os.path.exists(location):
                    os.startfile(location)
                else:
                    self.safe_log(f"Location not found: {location}", LogLevel.WARNING)
        except Exception as e:
            self.safe_log(f"Error opening location: {e}", LogLevel.ERROR)

    def _filter_programs_debounced(self, *args):
        """Debounced filter to avoid excessive filtering"""
        if hasattr(self, '_filter_timer'):
            self.root.after_cancel(self._filter_timer)
        
        self._filter_timer = self.root.after(300, self._filter_programs)

    def _filter_programs(self, *args):
        """Optimized program filtering with batch updates"""
        try:
            search_text = self.search_var.get().lower()
            publisher = self.publisher_filter.get()
            
            # Disable updates during filtering
            self.programs_tree.configure(selectmode='none')
            
            # Clear tree efficiently
            for item in self.programs_tree.get_children():
                self.programs_tree.delete(item)
            
            # Filter and insert in batches
            filtered_programs = [
                prog for prog in self.programs_data
                if (not search_text or search_text in prog.name.lower()) and
                   (not publisher or publisher == "All" or prog.publisher == publisher)
            ]
            
            # Batch insert for better performance
            for prog in filtered_programs:
                self._insert_program_item(prog)
            
            # Re-enable selection
            self.programs_tree.configure(selectmode='extended')
            
        except Exception as e:
            self.safe_log(f"Filter error: {e}", LogLevel.ERROR)

    def _insert_program_item(self, prog: ProgramInfo):
        """Insert program item into tree efficiently"""
        try:
            self.programs_tree.insert(
                "", "end",
                values=(
                    prog.name,
                    prog.publisher or "Unknown",
                    prog.version or "N/A",
                    prog.size or "N/A",
                    prog.install_date or "N/A",
                    prog.install_location or "N/A"
                )
            )
        except Exception as e:
            self.safe_log(f"Error inserting program: {e}", LogLevel.ERROR)

    def _sort_programs(self, column: str):
        """Sort programs by column"""
        try:
            # Get current sort order
            current_sort = getattr(self, '_sort_column', None)
            reverse = False
            
            if current_sort == column:
                reverse = getattr(self, '_sort_reverse', False)
                self._sort_reverse = not reverse
            else:
                self._sort_column = column
                self._sort_reverse = False
            
            # Sort data
            column_index = {
                "Name": 0, "Publisher": 1, "Version": 2,
                "Size": 3, "Install Date": 4, "Install Location": 5
            }
            
            idx = column_index.get(column, 0)
            
            items = [(self.programs_tree.item(item)['values'], item) 
                    for item in self.programs_tree.get_children()]
            
            items.sort(key=lambda x: x[0][idx] if len(x[0]) > idx else "", 
                      reverse=reverse)
            
            # Rearrange items
            for index, (values, item) in enumerate(items):
                self.programs_tree.move(item, '', index)
                
        except Exception as e:
            self.safe_log(f"Sort error: {e}", LogLevel.ERROR)

    def _setup_enhanced_logs_tab(self):
        """Setup logs tab - MUST create log_text widget"""
        frame = self.tabs["Logs"]
        
        # Header
        header = ttk.LabelFrame(frame, text="", padding=10)
        header.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(header, text="📑 System Logs", 
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        
        # Control buttons
        controls = ttk.Frame(header)
        controls.pack(side="right")
        
        tb.Button(controls, text="🗑️ Clear", bootstyle="warning",
                 command=self._clear_logs).pack(side="left", padx=5)
        
        tb.Button(controls, text="💾 Export", bootstyle="info",
                 command=self._export_logs).pack(side="left", padx=5)
        
        # Auto-scroll checkbox
        ttk.Checkbutton(controls, text="Auto-scroll", 
                       variable=self.auto_scroll_var).pack(side="left", padx=5)
        
        # Log text widget with color tags
        log_frame = ttk.Frame(frame)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.log_text = tk.Text(log_frame, wrap="word", height=20, 
                               font=("Consolas", 10), bg="#1E1E1E", fg="#D4D4D4")
        
        # Configure color tags
        self.log_text.tag_config("INFO", foreground="#4EC9B0")
        self.log_text.tag_config("SUCCESS", foreground="#4EC9B0", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("WARNING", foreground="#DCDCAA")
        self.log_text.tag_config("ERROR", foreground="#F48771", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("CRITICAL", foreground="#FF0000", 
                                font=("Consolas", 10, "bold"))
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.log_text.configure(state="disabled")

    def _clear_logs(self):
        """Clear log text"""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _export_logs(self):
        """Export logs to file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get("1.0", "end"))
                self.safe_log(f"Logs exported to {filename}", LogLevel.SUCCESS)
        except Exception as e:
            self.safe_log(f"Export error: {e}", LogLevel.ERROR)

    # ===== REST OF THE ORIGINAL METHODS =====
    # These are kept from the original implementation
    
    def _setup_deep_scanner_tab(self): 
        """Keep the original deep scanner tab implementation"""
        frame = self.tabs["Deep Scanner"]
        
        # Header
        header_frame = ttk.LabelFrame(frame, text="", padding=15)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(fill="x")
        
        ttk.Label(title_frame, text="🔍 Advanced Deep Scanner", 
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        
        ttk.Label(title_frame, text="Revo Uninstaller-style deep cleaning", 
                 font=("Segoe UI", 11), foreground="gray").pack(side="left", padx=(15, 0))
        
        # Scanner controls
        controls_frame = ttk.LabelFrame(frame, text="Scanner Controls", padding=15)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        # Program selection
        selection_frame = ttk.Frame(controls_frame)
        selection_frame.pack(fill="x", pady=10)
        
        ttk.Label(selection_frame, text="Program to scan:", 
                 font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 10))
        
        self.scan_program_var = tk.StringVar()
        self.scan_program_combo = ttk.Combobox(selection_frame, textvariable=self.scan_program_var, 
                                             width=50, font=("Segoe UI", 10))
        self.scan_program_combo.pack(side="left", padx=(0, 15))
        
        # Scan options
        options_frame = ttk.Frame(controls_frame)
        options_frame.pack(fill="x", pady=10)
        
        self.scan_registry_var = tk.BooleanVar(value=True)
        self.scan_files_var = tk.BooleanVar(value=True) 
        self.scan_shortcuts_var = tk.BooleanVar(value=True)
        self.scan_temp_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Registry entries", 
                       variable=self.scan_registry_var).pack(side="left", padx=10)
        ttk.Checkbutton(options_frame, text="Files & folders", 
                       variable=self.scan_files_var).pack(side="left", padx=10)
        ttk.Checkbutton(options_frame, text="Shortcuts", 
                       variable=self.scan_shortcuts_var).pack(side="left", padx=10)
        ttk.Checkbutton(options_frame, text="Temp files", 
                       variable=self.scan_temp_var).pack(side="left", padx=10)
        
        # Progress section
        progress_frame = ttk.LabelFrame(frame, text="Scan Progress", padding=15)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.deep_scan_progress = ttk.Progressbar(progress_frame, length=500, mode="determinate")
        self.deep_scan_progress.pack(pady=5)
        
        progress_labels_frame = ttk.Frame(progress_frame)
        progress_labels_frame.pack(fill="x", pady=5)
        
        self.deep_scan_status = ttk.Label(progress_labels_frame, text="Ready to scan", 
                                        font=("Segoe UI", 11))
        self.deep_scan_status.pack(side="left")
        
        self.deep_scan_detail = ttk.Label(progress_labels_frame, text="", 
                                        font=("Segoe UI", 9), foreground="gray")
        self.deep_scan_detail.pack(side="right")
        
        # Animation label
        self.deep_scan_animation = ttk.Label(progress_frame, text="", font=("Segoe UI", 12))
        self.deep_scan_animation.pack(pady=5)
        self.deep_scan_animator = SmoothAnimationHandler(self.deep_scan_animation)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Scan Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Results tree with categories
        columns = ("Item", "Type", "Size", "Category", "Confidence", "Path")
        self.deep_scan_tree = ttk.Treeview(results_frame, columns=columns, show="tree headings", height=12)
        
        self.deep_scan_tree.heading("#0", text="", anchor="w")
        self.deep_scan_tree.column("#0", width=0, stretch=False)
        
        result_column_widths = {"Item": 200, "Type": 80, "Size": 80, "Category": 100, 
                              "Confidence": 80, "Path": 400}
        
        for col in columns:
            self.deep_scan_tree.heading(col, text=col, anchor="w")
            self.deep_scan_tree.column(col, width=result_column_widths[col], anchor="w")
        
        # Results scrollbars
        results_v_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", 
                                          command=self.deep_scan_tree.yview)
        results_h_scrollbar = ttk.Scrollbar(results_frame, orient="horizontal", 
                                          command=self.deep_scan_tree.xview)
        self.deep_scan_tree.configure(yscrollcommand=results_v_scrollbar.set, 
                                    xscrollcommand=results_h_scrollbar.set)
        
        self.deep_scan_tree.pack(side="left", fill="both", expand=True)
        results_v_scrollbar.pack(side="right", fill="y")
        results_h_scrollbar.pack(side="bottom", fill="x")
        
        # Action buttons
        action_frame = ttk.Frame(frame)
        action_frame.pack(pady=15)
        
        self.start_deep_scan_btn = tb.Button(action_frame, text="🔍 Start Deep Scan", 
                                           bootstyle="primary", width=20,
                                           command=self.start_deep_scan)
        self.start_deep_scan_btn.pack(side="left", padx=10)
        
        self.clean_selected_btn = tb.Button(action_frame, text="🗑️ Clean Selected", 
                                          bootstyle="danger", width=20,
                                          command=self.clean_selected_leftovers, state="disabled")
        self.clean_selected_btn.pack(side="left", padx=10)
        
        self.clean_all_btn = tb.Button(action_frame, text="🧹 Clean All Safe", 
                                     bootstyle="warning", width=20,
                                     command=self.clean_safe_leftovers, state="disabled")
        self.clean_all_btn.pack(side="left", padx=10)
        
        self.cancel_scan_btn = tb.Button(action_frame, text="❌ Cancel", 
                                       bootstyle="secondary", width=15,
                                       command=self.cancel_deep_scan, state="disabled")
        self.cancel_scan_btn.pack(side="left", padx=10)

    def _setup_virus_scanner_tab(self): 
        """Keep the original virus scanner tab implementation"""
        frame = self.tabs["Virus Scanner"]
        
        # Header
        header_frame = ttk.LabelFrame(frame, text="", padding=15)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(fill="x")
        
        ttk.Label(title_frame, text="🛡️ Advanced Virus Scanner", 
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        
        # Defender status
        status_frame = ttk.Frame(header_frame)
        status_frame.pack(side="right")
        
        self.defender_status_label = ttk.Label(status_frame, text="Checking Defender status...", 
                                              font=("Segoe UI", 10))
        self.defender_status_label.pack(side="top")
        
        # Scanner controls
        controls_frame = ttk.LabelFrame(frame, text="Scanner Controls", padding=15)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        # Scan type selection
        scan_type_frame = ttk.Frame(controls_frame)
        scan_type_frame.pack(fill="x", pady=10)
        
        ttk.Label(scan_type_frame, text="Scan Type:", 
                 font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 10))
        
        self.scan_type_var = tk.StringVar(value="quick")
        ttk.Radiobutton(scan_type_frame, text="Quick Scan", variable=self.scan_type_var, 
                       value="quick").pack(side="left", padx=10)
        ttk.Radiobutton(scan_type_frame, text="Full System Scan", variable=self.scan_type_var, 
                       value="full").pack(side="left", padx=10)
        ttk.Radiobutton(scan_type_frame, text="Custom Scan", variable=self.scan_type_var, 
                       value="custom").pack(side="left", padx=10)
        
        # Custom scan path selection
        custom_scan_frame = ttk.Frame(controls_frame)
        custom_scan_frame.pack(fill="x", pady=10)
        
        ttk.Label(custom_scan_frame, text="Custom Path:", 
                 font=("Segoe UI", 10)).pack(side="left", padx=(0, 10))
        
        self.custom_scan_path = tk.StringVar()
        scan_path_entry = ttk.Entry(custom_scan_frame, textvariable=self.custom_scan_path, 
                                   width=50, font=("Segoe UI", 10))
        scan_path_entry.pack(side="left", padx=(0, 10))
        
        tb.Button(custom_scan_frame, text="Browse", bootstyle="secondary-outline",
                 command=self._browse_scan_path).pack(side="left")
        
        # Progress section
        progress_frame = ttk.LabelFrame(frame, text="Scan Progress", padding=15)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.virus_scan_progress = ttk.Progressbar(progress_frame, length=500, mode="determinate")
        self.virus_scan_progress.pack(pady=5)
        
        progress_labels_frame = ttk.Frame(progress_frame)
        progress_labels_frame.pack(fill="x", pady=5)
        
        self.virus_scan_status = ttk.Label(progress_labels_frame, text="Ready to scan", 
                                         font=("Segoe UI", 11))
        self.virus_scan_status.pack(side="left")
        
        self.virus_scan_detail = ttk.Label(progress_labels_frame, text="", 
                                         font=("Segoe UI", 9), foreground="gray")
        self.virus_scan_detail.pack(side="right")
        
        # Animation label
        self.virus_scan_animation = ttk.Label(progress_frame, text="", font=("Segoe UI", 12))
        self.virus_scan_animation.pack(pady=5)
        self.virus_scan_animator = SmoothAnimationHandler(self.virus_scan_animation)
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Scan Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Results tree
        columns = ("File", "Threat", "Severity", "Action", "Path")
        self.virus_scan_tree = ttk.Treeview(results_frame, columns=columns, show="tree headings", height=12)
        
        self.virus_scan_tree.heading("#0", text="", anchor="w")
        self.virus_scan_tree.column("#0", width=0, stretch=False)
        
        virus_column_widths = {"File": 200, "Threat": 150, "Severity": 100, "Action": 100, "Path": 400}
        
        for col in columns:
            self.virus_scan_tree.heading(col, text=col, anchor="w")
            self.virus_scan_tree.column(col, width=virus_column_widths[col], anchor="w")
        
        # Results scrollbars
        results_v_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", 
                                          command=self.virus_scan_tree.yview)
        results_h_scrollbar = ttk.Scrollbar(results_frame, orient="horizontal", 
                                          command=self.virus_scan_tree.xview)
        self.virus_scan_tree.configure(yscrollcommand=results_v_scrollbar.set, 
                                     xscrollcommand=results_h_scrollbar.set)
        
        self.virus_scan_tree.pack(side="left", fill="both", expand=True)
        results_v_scrollbar.pack(side="right", fill="y")
        results_h_scrollbar.pack(side="bottom", fill="x")
        
        # Action buttons
        action_frame = ttk.Frame(frame)
        action_frame.pack(pady=15)
        
        self.start_virus_scan_btn = tb.Button(action_frame, text="🛡️ Start Scan", 
                                            bootstyle="primary", width=15,
                                            command=self.start_virus_scan)
        self.start_virus_scan_btn.pack(side="left", padx=10)
        
        self.update_defender_btn = tb.Button(action_frame, text="🔄 Update Definitions", 
                                           bootstyle="info", width=20,
                                           command=self.update_defender_definitions)
        self.update_defender_btn.pack(side="left", padx=10)
        
        self.cancel_virus_scan_btn = tb.Button(action_frame, text="❌ Cancel", 
                                             bootstyle="secondary", width=15,
                                             command=self.cancel_virus_scan, state="disabled")
        self.cancel_virus_scan_btn.pack(side="left", padx=10)
        
        # Initialize virus scanner status
        self._update_defender_status()

    def _setup_smart_automation_tab(self): 
        """Setup the Smart Automation tab with optimization profiles"""
        frame = self.tabs["Smart Automation"]
    
        try:
            # Create the smart automation widget
            self.smart_automation_widget = SmartAutomationWidget(frame, self.smart_automation)
            self.logger.log("Smart Automation initialized successfully", LogLevel.SUCCESS)
            
        except Exception as e:
            self.logger.log(f"Failed to initialize Smart Automation: {str(e)}", LogLevel.ERROR)
            # Show error message in the tab
            error_frame = ttk.LabelFrame(frame, text="Smart Automation Error", padding=20)
            error_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
            ttk.Label(error_frame, 
                    text=f"Failed to initialize Smart Automation:\n{str(e)}",
                    font=("Segoe UI", 12),
                    justify=tk.CENTER).pack(expand=True)

    def _setup_enhanced_startup_tab(self): 
        """Enhanced startup manager tab"""
        frame = self.tabs["Startup"]
        
        # Header
        header_frame = ttk.LabelFrame(frame, text="", padding=15)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(fill="x")
        
        ttk.Label(title_frame, text="Startup Programs Manager", 
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        
        # Progress section
        progress_frame = ttk.Frame(title_frame)
        progress_frame.pack(side="right")
        
        self.startup_progress = ttk.Progressbar(progress_frame, length=200, mode="determinate")
        self.startup_progress.pack(side="top", pady=2)
        
        self.startup_status = ttk.Label(progress_frame, text="Ready", font=("Segoe UI", 10))
        self.startup_status.pack(side="top")
        
        # Startup list
        list_frame = ttk.LabelFrame(frame, text="Startup Programs", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Name", "Path", "Registry Location")
        self.startup_tree = ttk.Treeview(list_frame, columns=columns, show="tree headings", height=15)
        
        self.startup_tree.heading("#0", text="", anchor="w")
        self.startup_tree.column("#0", width=0, stretch=False)
        
        startup_column_widths = {"Name": 200, "Path": 400, "Registry Location": 300}
        for col in columns:
            self.startup_tree.heading(col, text=col, anchor="w")
            self.startup_tree.column(col, width=startup_column_widths[col], anchor="w")
        
        # Scrollbars
        startup_v_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.startup_tree.yview)
        startup_h_scrollbar = ttk.Scrollbar(list_frame, orient="horizontal", command=self.startup_tree.xview)
        self.startup_tree.configure(yscrollcommand=startup_v_scrollbar.set, xscrollcommand=startup_h_scrollbar.set)
        
        self.startup_tree.pack(side="left", fill="both", expand=True)
        startup_v_scrollbar.pack(side="right", fill="y")
        startup_h_scrollbar.pack(side="bottom", fill="x")

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)
        
        self.refresh_startup_btn = tb.Button(btn_frame, text="Refresh List", 
                                           bootstyle="info", width=15,
                                           command=self.refresh_startup_programs)
        self.refresh_startup_btn.pack(side="left", padx=8)
        
        self.remove_startup_btn = tb.Button(btn_frame, text="Remove Selected", 
                                          bootstyle="danger", width=18,
                                          command=self.remove_startup_program)
        self.remove_startup_btn.pack(side="left", padx=8)

    def _setup_enhanced_cleaner_tab(self): 
        """Enhanced junk cleaner tab with better UI"""
        frame = self.tabs["Cleaner"]
        
        # Header
        header_frame = ttk.LabelFrame(frame, text="", padding=15)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(header_frame, text="Advanced Junk Cleaner", 
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        
        # Progress section with enhanced styling
        progress_frame = ttk.LabelFrame(frame, text="Cleaning Progress", padding=15)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.junk_progress = ttk.Progressbar(progress_frame, length=500, mode="determinate",
                                           style="success.Horizontal.TProgressbar")
        self.junk_progress.pack(pady=5)
        
        progress_labels = ttk.Frame(progress_frame)
        progress_labels.pack(fill="x", pady=5)
        
        self.junk_status = ttk.Label(progress_labels, text="Ready to scan for junk files", 
                                   font=("Segoe UI", 11))
        self.junk_status.pack(side="left")
        
        self.junk_animation_label = ttk.Label(progress_labels, text="", font=("Segoe UI", 12))
        self.junk_animation_label.pack(side="right")
        self.junk_animator = SmoothAnimationHandler(self.junk_animation_label)
        
        # Enhanced statistics with cards
        stats_frame = ttk.LabelFrame(frame, text="Cleaning Statistics", padding=20)
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        stats_container = ttk.Frame(stats_frame)
        stats_container.pack(expand=True)
        
        # Create stat cards
        stat_cards = ttk.Frame(stats_container)
        stat_cards.pack(expand=True)
        
        # Files Found Card
        found_card = ttk.Frame(stat_cards, relief="raised", borderwidth=1)
        found_card.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        ttk.Label(found_card, text="Files Found", font=("Segoe UI", 10, "bold")).pack(pady=5)
        self.files_found_label = ttk.Label(found_card, text="0", font=("Segoe UI", 16, "bold"), foreground="blue")
        self.files_found_label.pack(pady=5)
        
        # Total Size Card
        size_card = ttk.Frame(stat_cards, relief="raised", borderwidth=1)
        size_card.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ttk.Label(size_card, text="Total Size", font=("Segoe UI", 10, "bold")).pack(pady=5)
        self.total_size_label = ttk.Label(size_card, text="0 MB", font=("Segoe UI", 16, "bold"), foreground="orange")
        self.total_size_label.pack(pady=5)
        
        # Files Cleaned Card
        cleaned_card = ttk.Frame(stat_cards, relief="raised", borderwidth=1)
        cleaned_card.grid(row=0, column=2, padx=10, pady=10, sticky="ew")
        ttk.Label(cleaned_card, text="Files Cleaned", font=("Segoe UI", 10, "bold")).pack(pady=5)
        self.files_cleaned_label = ttk.Label(cleaned_card, text="0", font=("Segoe UI", 16, "bold"), foreground="green")
        self.files_cleaned_label.pack(pady=5)
        
        # Space Freed Card
        freed_card = ttk.Frame(stat_cards, relief="raised", borderwidth=1)
        freed_card.grid(row=0, column=3, padx=10, pady=10, sticky="ew")
        ttk.Label(freed_card, text="Space Freed", font=("Segoe UI", 10, "bold")).pack(pady=5)
        self.space_freed_label = ttk.Label(freed_card, text="0 MB", font=("Segoe UI", 16, "bold"), foreground="purple")
        self.space_freed_label.pack(pady=5)
        
        for i in range(4):
            stat_cards.columnconfigure(i, weight=1)
        
        # Enhanced buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        self.scan_junk_btn = tb.Button(btn_frame, text="Scan for Junk", 
                                     bootstyle="info", width=18,
                                     command=self.scan_junk_files)
        self.scan_junk_btn.pack(side="left", padx=10)
        
        self.clean_junk_btn = tb.Button(btn_frame, text="Clean Junk Files", 
                                      bootstyle="success", width=18,
                                      command=self.clean_junk_files, state="disabled")
        self.clean_junk_btn.pack(side="left", padx=10)
        
        self.cancel_junk_btn = tb.Button(btn_frame, text="Cancel Operation", 
                                       bootstyle="danger", width=18,
                                       command=self.cancel_junk_operation, state="disabled")
        self.cancel_junk_btn.pack(side="left", padx=10)
        
        self.junk_files = []
        self.junk_progress_handler = None

    def _setup_enhanced_tools_tab(self): 
        """Enhanced tools tab with better organization"""
        frame = self.tabs["Tools"]
        
        # Header
        ttk.Label(frame, text="Windows System Tools", 
                 font=("Segoe UI", 18, "bold")).pack(pady=20)
        
        # Tools organized in categories
        categories = {
            "System Management": {
                "Registry Editor": ("regedit.exe", ""),
                "Task Manager": ("taskmgr.exe", ""),
                "System Configuration": ("msconfig.exe", ""),
                "Services": ("services.msc", "")
            },
            "Disk & File Management": {
                "Disk Cleanup": ("cleanmgr.exe", ""),
                "Disk Management": ("diskmgmt.msc", ""),
                "Computer Management": ("compmgmt.msc", ""),
                "Resource Monitor": ("resmon.exe", "")
            },
            "System Information": {
                "System Information": ("msinfo32.exe", ""),
                "Device Manager": ("devmgmt.msc", ""),
                "Event Viewer": ("eventvwr.msc", ""),
                "Group Policy Editor": ("gpedit.msc", "")
            }
        }
        
        tools_container = ttk.Frame(frame)
        tools_container.pack(fill="both", expand=True, padx=20)
        
        row = 0
        for category, tools in categories.items():
            # Category header
            category_frame = ttk.LabelFrame(tools_container, text=category, padding=15)
            category_frame.pack(fill="x", pady=10)
            
            # Tools grid
            tools_grid = ttk.Frame(category_frame)
            tools_grid.pack(expand=True, fill="x")
            
            col = 0
            for name, (exe, desc) in tools.items():
                btn = tb.Button(tools_grid, text=name, 
                              bootstyle="secondary-outline", width=20,
                              command=lambda e=exe, n=name: self.launch_tool(n, e))
                btn.grid(row=0, column=col, padx=8, pady=8, sticky="ew")
                col += 1
                if col > 3:
                    col = 0
            
            for i in range(4):
                tools_grid.columnconfigure(i, weight=1)

    def _setup_enhanced_settings_tab(self): 
        """Enhanced settings tab with better organization"""
        frame = self.tabs["Settings"]
        
        # Header
        ttk.Label(frame, text="Application Settings", 
                 font=("Segoe UI", 18, "bold")).pack(pady=20)
        
        settings_container = ttk.Frame(frame)
        settings_container.pack(fill="both", expand=True, padx=20)
        
        # Appearance Settings
        appearance_frame = ttk.LabelFrame(settings_container, text="Appearance", padding=20)
        appearance_frame.pack(fill="x", pady=10)
        
        theme_frame = ttk.Frame(appearance_frame)
        theme_frame.pack(fill="x", pady=10)
        
        ttk.Label(theme_frame, text="Theme:", font=("Segoe UI", 11, "bold")).pack(side="left")
        
        self.theme_var = tk.StringVar(value="cosmo")
        theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var, width=15, state="readonly")
        theme_combo['values'] = ['cosmo', 'flatly', 'journal', 'litera', 'lumen', 'minty', 'pulse', 'sandstone', 'united', 'yeti', 'superhero', 'solar', 'cyborg', 'vapor']
        theme_combo.pack(side="left", padx=(10, 0))
        theme_combo.bind('<<ComboboxSelected>>', self._change_theme)
        
        # System Information
        system_frame = ttk.LabelFrame(settings_container, text="System Information", padding=20)
        system_frame.pack(fill="x", pady=10)
        
        admin_status = "Administrator" if is_admin() else "Standard User"
        admin_color = "green" if is_admin() else "orange"
        
        ttk.Label(system_frame, text=f"Running as: {admin_status}", 
                 font=("Segoe UI", 11), foreground=admin_color).pack(anchor="w", pady=5)
        
        if not is_admin():
            tb.Button(system_frame, text="Request Administrator Privileges",
                     bootstyle="warning-outline", 
                     command=run_as_admin).pack(anchor="w", pady=5)
        
        # Performance Settings
        performance_frame = ttk.LabelFrame(settings_container, text="Performance", padding=20)
        performance_frame.pack(fill="x", pady=10)
        
        ttk.Label(performance_frame, text=f"Thread Pool Size: {self.thread_pool._max_workers}").pack(anchor="w", pady=5)
        ttk.Label(performance_frame, text=f"Active Operations: {len(self.active_operations)}").pack(anchor="w", pady=5)

    # ===== KEEP ALL THE ORIGINAL FUNCTIONALITY METHODS =====

    def refresh_installed_programs(self):
        """Enhanced program refresh with better progress tracking"""
        if "refresh_programs" in self.active_operations:
            return
            
        self.active_operations.add("refresh_programs")
        self._set_programs_buttons_state(scanning=True)
        self.programs_animator.start('scanning', "Loading programs")
        
        progress_handler = EnhancedProgressHandler(
            self.programs_progress, 
            self.programs_status, 
            self.programs_animation_label
        )
        progress_handler.set_indeterminate(True)
        
        def update_progress(current, total, message, detail=""):
            self.root.after(0, lambda: progress_handler.update(current, total, message, detail))
        
        def on_complete(future):
            try:
                programs = future.result()
                self.root.after(0, lambda: self._update_programs_tree_enhanced(programs, progress_handler))
            except Exception as e:
                self.logger.log(f"Failed to refresh programs: {str(e)}", LogLevel.ERROR)
            finally:
                self.active_operations.discard("refresh_programs")
                self.root.after(0, lambda: self._set_programs_buttons_state(scanning=False))
        
        future = self.thread_pool.submit(
            EnhancedRegistryHelper.get_installed_programs_async, 
            update_progress
        )
        future.add_done_callback(on_complete)

    def _update_programs_tree_enhanced(self, programs: List[ProgramInfo], 
                                     progress_handler: EnhancedProgressHandler):
        """Update programs tree with enhanced information"""
        # Clear existing items
        for item in self.programs_tree.get_children():
            self.programs_tree.delete(item)
        
        self.programs_data = programs
        
        # Update publisher filter
        publishers = sorted(set(p.publisher for p in programs if p.publisher))
        self.publisher_filter['values'] = ['All'] + publishers
        self.publisher_filter.set('All')
        
        # Update scan program combo
        program_names = [p.name for p in programs]
        self.scan_program_combo['values'] = program_names
        
        # Add programs to tree
        for program in programs:
            self.programs_tree.insert("", "end", values=(
                program.name,
                program.publisher or "Unknown",
                program.version or "N/A", 
                program.size or "Unknown",
                program.install_date or "Unknown",
                program.install_location or "Unknown"
            ))
        
        progress_handler.set_indeterminate(False)
        progress_handler.reset()
        self.programs_animator.stop()
        self.logger.log(f"✅ Loaded {len(programs)} installed programs with detailed information", LogLevel.SUCCESS)

    def _set_programs_buttons_state(self, scanning: bool = False):
        """Manage programs tab button states"""
        state = "disabled" if scanning else "normal"
        self.refresh_programs_btn.configure(state=state)
        self.uninstall_btn.configure(state=state)
        self.quick_scan_btn.configure(state=state)

    def smart_uninstall_program(self):
        """Enhanced uninstall with automatic deep scan"""
        selected = self.programs_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a program to uninstall.")
            return
            
        item = self.programs_tree.item(selected[0])
        program_name = item["values"][0]
        
        # Find program info
        program_info = None
        for prog in self.programs_data:
            if prog.name == program_name:
                program_info = prog
                break
        
        if not program_info or not program_info.uninstall_command:
            messagebox.showinfo("Info", "Uninstall command not found for this program.")
            return
            
        # Confirm uninstall
        result = messagebox.askyesnocancel(
            "Smart Uninstall Confirmation", 
            f"Smart Uninstall will:\n\n"
            f"1. Run the program's uninstaller\n"
            f"2. Automatically scan for leftovers\n"
            f"3. Show detailed cleanup options\n\n"
            f"Uninstall '{program_name}'?"
        )
        
        if result is None:  # Cancel
            return
        elif not result:  # No
            return
            
        self.logger.log(f"🚀 Starting smart uninstall of {program_name}", LogLevel.INFO)
        
        def run_smart_uninstall():
            try:
                # Step 1: Run uninstaller
                self.logger.log(f"📦 Running uninstaller for {program_name}", LogLevel.INFO)
                process = subprocess.Popen(program_info.uninstall_command, shell=True)
                process.wait()
                
                self.logger.log(f"✅ Uninstaller completed for {program_name}", LogLevel.SUCCESS)
                
                # Step 2: Wait a moment for filesystem to settle
                time.sleep(2)
                
                # Step 3: Auto-trigger deep scan
                self.root.after(0, lambda: self._auto_deep_scan(program_info))
                
            except Exception as e:
                self.logger.log(f"❌ Smart uninstall failed for {program_name}: {str(e)}", LogLevel.ERROR)
        
        self.thread_pool.submit(run_smart_uninstall)

    def _auto_deep_scan(self, program_info: ProgramInfo):
        """Automatically trigger deep scan after uninstall"""
        # Switch to Deep Scanner tab
        for i, tab_id in enumerate(self.notebook.tabs()):
            if "Deep Scanner" in self.notebook.tab(tab_id, "text"):
                self.notebook.select(i)
                break
        
        # Set the program in the combo box
        self.scan_program_combo.set(program_info.name)
        
        # Show notification
        self.logger.log(f"🔍 Starting automatic deep scan for {program_info.name}", LogLevel.SCAN)
        
        # Start deep scan
        self.root.after(1000, self.start_deep_scan)  # Small delay for UI update

    def start_deep_scan(self):
        """Start the deep scanning process"""
        program_name = self.scan_program_combo.get()
        if not program_name:
            messagebox.showwarning("Warning", "Please select a program to scan.")
            return
            
        # Find program info for install location
        install_location = ""
        for prog in self.programs_data:
            if prog.name == program_name:
                install_location = prog.install_location
                break
        
        self.active_operations.add("deep_scan")
        self._set_deep_scan_buttons_state(scanning=True)
        
        # Clear previous results
        for item in self.deep_scan_tree.get_children():
            self.deep_scan_tree.delete(item)
        
        self.deep_scan_animator.start('analyzing', "Deep scanning")
        
        progress_handler = EnhancedProgressHandler(
            self.deep_scan_progress,
            self.deep_scan_status,
            self.deep_scan_detail
        )
        
        def update_progress(current, total, message, detail=""):
            self.root.after(0, lambda: progress_handler.update(current, total, message, detail))
        
        def on_scan_complete(future):
            try:
                scan_result = future.result()
                self.root.after(0, lambda: self._display_deep_scan_results(scan_result, progress_handler))
            except Exception as e:
                self.logger.log(f"Deep scan failed: {str(e)}", LogLevel.ERROR)
            finally:
                self.active_operations.discard("deep_scan")
                self.root.after(0, lambda: self._set_deep_scan_buttons_state(scanning=False))
        
        # Set scanner logger
        self.deep_scanner.logger = self.logger
        
        future = self.thread_pool.submit(
            self.deep_scanner.deep_scan_leftovers,
            program_name,
            install_location,
            update_progress
        )
        future.add_done_callback(on_scan_complete)

    def _display_deep_scan_results(self, scan_result: DeepScanResult, 
                                 progress_handler: EnhancedProgressHandler):
        """Display deep scan results in the tree"""
        self.last_scan_result = scan_result
        
        # Group items by category for better organization
        categories = {}
        for item in scan_result.leftover_items:
            if item.category not in categories:
                categories[item.category] = []
            categories[item.category].append(item)
        
        # Add category nodes and items
        for category, items in categories.items():
            category_icons = {
                'program_files': '📁',
                'appdata': '👤', 
                'registry': '📝',
                'shortcuts': '🔗',
                'temp': '🗂️',
                'system': '⚙️'
            }
            
            category_icon = category_icons.get(category, '📄')
            category_name = category.replace('_', ' ').title()
            
            # Insert category parent
            category_id = self.deep_scan_tree.insert("", "end", 
                values=(f"{category_icon} {category_name} ({len(items)} items)", 
                       "Category", self._format_bytes(sum(i.size for i in items)), 
                       "", "", ""),
                tags=("category",)
            )
            
            # Add items under category
            for item in items:
                item_name = item.path.name
                if len(item_name) > 50:
                    item_name = item_name[:47] + "..."
                
                confidence_colors = {
                    "High": "🔴", "Medium": "🟡", "Low": "🟢"
                }
                confidence_icon = confidence_colors.get(item.confidence, "⚪")
                
                self.deep_scan_tree.insert(category_id, "end",
                    values=(
                        item_name,
                        item.item_type.title(),
                        self._format_bytes(item.size) if item.size else "N/A",
                        item.category.replace('_', ' ').title(),
                        f"{confidence_icon} {item.confidence}",
                        str(item.path)
                    ),
                    tags=(f"confidence_{item.confidence.lower()}",)
                )
        
        # Configure tags for visual distinction
        self.deep_scan_tree.tag_configure("category", background="#E8F4FD", font=("Segoe UI", 10, "bold"))
        self.deep_scan_tree.tag_configure("confidence_high", background="#FFEBEE")
        self.deep_scan_tree.tag_configure("confidence_medium", background="#FFF3E0") 
        self.deep_scan_tree.tag_configure("confidence_low", background="#E8F5E8")
        
        # Expand all categories
        for item in self.deep_scan_tree.get_children():
            self.deep_scan_tree.item(item, open=True)
        
        # Update UI
        progress_handler.reset()
        self.deep_scan_animator.stop()
        
        # Enable action buttons
        if scan_result.leftover_items:
            self.clean_selected_btn.configure(state="normal")
            self.clean_all_btn.configure(state="normal")
        
        # Log results
        total_items = len(scan_result.leftover_items)
        total_size = self._format_bytes(scan_result.total_size)
        scan_time = f"{scan_result.scan_time:.1f}s"
        
        self.logger.log(
            f"🔍 Deep scan complete: {total_items} leftovers found "
            f"({total_size}) in {scan_time}", 
            LogLevel.SUCCESS
        )

    def _set_deep_scan_buttons_state(self, scanning: bool = False, cleaning: bool = False):
        """Manage deep scan button states"""
        self.start_deep_scan_btn.configure(state="disabled" if scanning or cleaning else "normal")
        self.cancel_scan_btn.configure(state="normal" if scanning or cleaning else "disabled")
        
        if not scanning and not cleaning and self.last_scan_result:
            self.clean_selected_btn.configure(state="normal")
            self.clean_all_btn.configure(state="normal")
        else:
            self.clean_selected_btn.configure(state="disabled")
            self.clean_all_btn.configure(state="disabled")

    def clean_selected_leftovers(self):
        """Clean selected leftover items"""
        selected_items = self.deep_scan_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select items to clean.")
            return
        
        # Get actual leftover items (not categories)
        items_to_clean = []
        for item_id in selected_items:
            item_values = self.deep_scan_tree.item(item_id)["values"]
            if len(item_values) >= 6 and item_values[1] != "Category":
                # This is an actual leftover item, not a category
                item_path = Path(item_values[5])  # Path is in column 5
                for leftover in self.last_scan_result.leftover_items:
                    if leftover.path == item_path:
                        items_to_clean.append(leftover)
                        break
        
        if not items_to_clean:
            messagebox.showwarning("Warning", "No valid items selected for cleaning.")
            return
        
        self._clean_leftovers(items_to_clean)

    def clean_safe_leftovers(self):
        """Clean all leftovers marked as safe (High and Medium confidence)"""
        if not self.last_scan_result:
            return
        
        safe_items = [item for item in self.last_scan_result.leftover_items 
                     if item.confidence in ["High", "Medium"]]
        
        if not safe_items:
            messagebox.showinfo("Info", "No safe items found to clean.")
            return
        
        result = messagebox.askyesno(
            "Clean Safe Items",
            f"This will clean {len(safe_items)} items marked as High or Medium confidence.\n\n"
            f"Continue with safe cleanup?"
        )
        
        if result:
            self._clean_leftovers(safe_items)

    def _clean_leftovers(self, items_to_clean: List[LeftoverItem]):
        """Clean the specified leftover items"""
        if not items_to_clean:
            return
            
        total_size = sum(item.size for item in items_to_clean)
        
        result = messagebox.askyesno(
            "Confirm Cleanup",
            f"This will permanently delete {len(items_to_clean)} items "
            f"({self._format_bytes(total_size)}).\n\n"
            f"⚠️ This action cannot be undone!\n\n"
            f"Continue?"
        )
        
        if not result:
            return
        
        self._set_deep_scan_buttons_state(cleaning=True)
        self.deep_scan_animator.start('cleaning', "Cleaning leftovers")
        
        progress_handler = EnhancedProgressHandler(
            self.deep_scan_progress,
            self.deep_scan_status,
            self.deep_scan_detail
        )
        
        def update_progress(current, total, message, detail=""):
            self.root.after(0, lambda: progress_handler.update(current, total, message, detail))
        
        def on_clean_complete(future):
            try:
                cleaned_count, errors = future.result()
                self.root.after(0, lambda: self._finalize_cleanup(cleaned_count, errors, progress_handler))
            except Exception as e:
                self.logger.log(f"Cleanup failed: {str(e)}", LogLevel.ERROR)
            finally:
                self.root.after(0, lambda: self._set_deep_scan_buttons_state(cleaning=False))
        
        future = self.thread_pool.submit(
            self._perform_cleanup,
            items_to_clean,
            update_progress
        )
        future.add_done_callback(on_clean_complete)

    def _perform_cleanup(self, items_to_clean: List[LeftoverItem], 
                        progress_callback: Optional[Callable] = None) -> Tuple[int, int]:
        """Perform the actual cleanup of leftover items"""
        cleaned_count = 0
        error_count = 0
        
        for i, item in enumerate(items_to_clean):
            if progress_callback:
                progress_callback(i, len(items_to_clean), "Cleaning leftovers", str(item.path))
            
            try:
                if item.item_type == "registry":
                    # Handle registry cleanup
                    self._clean_registry_item(item)
                    cleaned_count += 1
                elif item.path.exists():
                    if item.path.is_dir():
                        shutil.rmtree(item.path, ignore_errors=True)
                    else:
                        item.path.unlink()
                    cleaned_count += 1
                    
            except Exception as e:
                error_count += 1
                self.logger.log(f"Failed to clean {item.path}: {str(e)}", LogLevel.WARNING)
        
        return cleaned_count, error_count

    def _clean_registry_item(self, item: LeftoverItem):
        """Clean a registry item"""
        # This is a simplified registry cleanup - in practice you'd need more sophisticated handling
        try:
            path_parts = str(item.path).split('\\')
            if len(path_parts) >= 2:
                hive_name = path_parts[0]
                key_path = '\\'.join(path_parts[1:])
                
                hive_map = {
                    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE
                }
                
                if hive_name in hive_map:
                    parent_path = '\\'.join(path_parts[1:-1])
                    key_name = path_parts[-1]
                    
                    try:
                        key = winreg.OpenKey(hive_map[hive_name], parent_path, 0, winreg.KEY_SET_VALUE)
                        winreg.DeleteKey(key, key_name)
                        winreg.CloseKey(key)
                    except FileNotFoundError:
                        pass  # Already deleted
        except Exception:
            pass  # Registry cleanup failed, continue

    def _finalize_cleanup(self, cleaned_count: int, error_count: int, progress_handler: EnhancedProgressHandler):
        """Finalize the cleanup process"""
        progress_handler.reset()
        self.deep_scan_animator.stop()
        
        # Remove cleaned items from the tree
        if cleaned_count > 0:
            self._refresh_scan_results()
        
        # Log results
        if error_count == 0:
            self.logger.log(f"Cleanup completed successfully: {cleaned_count} items removed", LogLevel.SUCCESS)
        else:
            self.logger.log(f"Cleanup completed: {cleaned_count} items removed, {error_count} errors", LogLevel.WARNING)
        
        messagebox.showinfo("Cleanup Complete", 
                           f"Cleanup finished!\n\n"
                           f"Items removed: {cleaned_count}\n"
                           f"Errors: {error_count}")

    def _refresh_scan_results(self):
        """Refresh the scan results after cleanup"""
        if self.last_scan_result:
            # Re-run the scan to show current state
            program_name = self.last_scan_result.program_name
            self.root.after(1000, lambda: self._auto_rescan_after_cleanup(program_name))

    def _auto_rescan_after_cleanup(self, program_name: str):
        """Automatically rescan after cleanup to show remaining items"""
        self.scan_program_combo.set(program_name)
        self.start_deep_scan()

    def cancel_deep_scan(self):
        """Cancel the deep scan operation"""
        self.active_operations.discard("deep_scan")
        self._set_deep_scan_buttons_state(scanning=False)
        self.deep_scan_animator.stop()
        self.logger.log("Deep scan cancelled", LogLevel.WARNING)

    def quick_scan_leftovers(self):
        """Quick scan for leftovers of selected program"""
        selected = self.programs_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a program for quick scan.")
            return
            
        item = self.programs_tree.item(selected[0])
        program_name = item["values"][0]
        
        # Set program in deep scanner and switch tabs
        self.scan_program_combo.set(program_name)
        
        # Switch to Deep Scanner tab
        for i, tab_id in enumerate(self.notebook.tabs()):
            if "Deep Scanner" in self.notebook.tab(tab_id, "text"):
                self.notebook.select(i)
                break
        
        # Start scan after small delay
        self.root.after(500, self.start_deep_scan)

    def refresh_startup_programs(self):
        """Enhanced startup program refresh"""
        if "refresh_startup" in self.active_operations:
            return
            
        self.active_operations.add("refresh_startup")
        self.refresh_startup_btn.configure(state="disabled")
        
        progress_handler = EnhancedProgressHandler(self.startup_progress, self.startup_status)
        progress_handler.set_indeterminate(True)
        
        def update_progress(current, total, message, detail=""):
            self.root.after(0, lambda: progress_handler.update(current, total, message, detail))
        
        def on_complete(future):
            try:
                items = future.result()
                self.root.after(0, lambda: self._update_startup_tree_enhanced(items, progress_handler))
            except Exception as e:
                self.logger.log(f"Failed to refresh startup programs: {str(e)}", LogLevel.ERROR)
            finally:
                self.active_operations.discard("refresh_startup")
                self.root.after(0, lambda: self.refresh_startup_btn.configure(state="normal"))
        
        future = self.thread_pool.submit(
            EnhancedRegistryHelper.get_startup_programs_async, 
            update_progress
        )
        future.add_done_callback(on_complete)

    def _update_startup_tree_enhanced(self, items: List[StartupItem], 
                                    progress_handler: EnhancedProgressHandler):
        """Update startup tree with enhanced information"""
        for item in self.startup_tree.get_children():
            self.startup_tree.delete(item)
        
        self.startup_data = items
        
        for item in items:
            registry_location = f"{'HKCU' if item.hive == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{item.registry_path.split('\\')[-1]}"
            self.startup_tree.insert("", "end", values=(item.name, item.path, registry_location))
        
        progress_handler.set_indeterminate(False)
        progress_handler.reset()
        self.logger.log(f"Found {len(items)} startup programs", LogLevel.SUCCESS)

    def remove_startup_program(self):
        """Enhanced startup program removal"""
        selected = self.startup_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a startup entry to remove.")
            return
            
        item = self.startup_tree.item(selected[0])
        program_name = item["values"][0]
        
        startup_item = None
        for item_data in self.startup_data:
            if item_data.name == program_name:
                startup_item = item_data
                break
        
        if not startup_item:
            messagebox.showerror("Error", "Could not find startup entry data.")
            return
            
        if messagebox.askyesno("Confirm", f"Remove startup entry '{program_name}'?"):
            def remove_entry():
                try:
                    if EnhancedRegistryHelper.remove_startup_entry(startup_item):
                        self.logger.log(f"Removed startup entry '{program_name}'", LogLevel.SUCCESS)
                        self.root.after(0, self.refresh_startup_programs)
                    else:
                        self.logger.log(f"Failed to remove '{program_name}'", LogLevel.ERROR)
                except Exception as e:
                    self.logger.log(f"Error removing '{program_name}': {str(e)}", LogLevel.ERROR)
            
            self.thread_pool.submit(remove_entry)

    def scan_junk_files(self):
        """Enhanced junk file scanning"""
        if "scan_junk" in self.active_operations:
            return
            
        self.active_operations.add("scan_junk")
        self._set_junk_buttons_state(scanning=True)
        self.junk_animator.start('scanning', "Scanning for junk")
        
        self.junk_progress_handler = EnhancedProgressHandler(
            self.junk_progress, self.junk_status, self.junk_animation_label
        )
        self.junk_progress_handler.set_indeterminate(True)
        
        def update_progress(current, total, message, detail=""):
            if self.junk_progress_handler and not self.junk_progress_handler.is_cancelled:
                self.root.after(0, lambda: self.junk_progress_handler.update(current, total, message, detail))
        
        def on_scan_complete(future):
            try:
                if not self.junk_progress_handler.is_cancelled:
                    files = future.result()
                    self.root.after(0, lambda: self._update_junk_scan_results_enhanced(files))
            except Exception as e:
                self.logger.log(f"Junk scan failed: {str(e)}", LogLevel.ERROR)
            finally:
                self.active_operations.discard("scan_junk")
                self.root.after(0, lambda: self._set_junk_buttons_state(scanning=False))
        
        future = self.thread_pool.submit(
            AsyncJunkCleaner.scan_junk_files,
            update_progress
        )
        future.add_done_callback(on_scan_complete)

    def _update_junk_scan_results_enhanced(self, files: List[Path]):
        """Update junk scan results with enhanced UI"""
        self.junk_files = files
        
        if self.junk_progress_handler:
            self.junk_progress_handler.set_indeterminate(False)
            self.junk_progress_handler.reset()
        
        self.junk_animator.stop()
        
        total_size = 0
        for file_path in files:
            try:
                total_size += file_path.stat().st_size
            except (OSError, FileNotFoundError):
                continue
        
        # Update stat cards with animation-like effect
        self._animate_counter(self.files_found_label, 0, len(files), "")
        self._animate_counter(self.total_size_label, 0, total_size, "bytes")
        
        self.files_cleaned_label.config(text="0")
        self.space_freed_label.config(text="0 B")
        
        self.junk_status.config(text=f"Found {len(files)} junk files ({self._format_bytes(total_size)})")
        
        if files:
            self.clean_junk_btn.config(state="normal")
            self.logger.log(f"Scan complete: {len(files)} junk files found ({self._format_bytes(total_size)})", LogLevel.SUCCESS)
        else:
            self.logger.log("Scan complete: No junk files found", LogLevel.INFO)

    def clean_junk_files(self):
        """Enhanced junk file cleaning"""
        if not self.junk_files or "clean_junk" in self.active_operations:
            return
            
        total_size = 0
        for file_path in self.junk_files:
            try:
                total_size += file_path.stat().st_size
            except (OSError, FileNotFoundError):
                continue
        
        result = messagebox.askyesno(
            "Clean Junk Files",
            f"This will delete {len(self.junk_files)} junk files "
            f"({self._format_bytes(total_size)}).\n\n"
            f"Continue with cleanup?"
        )
        
        if not result:
            return
            
        self.active_operations.add("clean_junk")
        self._set_junk_buttons_state(cleaning=True)
        self.junk_animator.start('cleaning', "Cleaning junk files")
        
        self.junk_progress_handler = EnhancedProgressHandler(
            self.junk_progress, self.junk_status, self.junk_animation_label
        )
        
        def update_progress(current, total, message, detail=""):
            if self.junk_progress_handler and not self.junk_progress_handler.is_cancelled:
                self.root.after(0, lambda: self.junk_progress_handler.update(current, total, message, detail))
        
        def on_clean_complete(future):
            try:
                cleaned_count, total_freed = future.result()
                self.root.after(0, lambda: self._finalize_junk_cleanup(cleaned_count, total_freed))
            except Exception as e:
                self.logger.log(f"Junk cleanup failed: {str(e)}", LogLevel.ERROR)
            finally:
                self.active_operations.discard("clean_junk")
                self.root.after(0, lambda: self._set_junk_buttons_state(cleaning=False))
        
        future = self.thread_pool.submit(
            AsyncJunkCleaner.clean_junk_files,
            self.junk_files,
            update_progress
        )
        future.add_done_callback(on_clean_complete)

    def _finalize_junk_cleanup(self, cleaned_count: int, total_freed: int):
        """Finalize junk cleanup process"""
        if self.junk_progress_handler:
            self.junk_progress_handler.reset()
        
        self.junk_animator.stop()
        
        # Update stat cards
        self._animate_counter(self.files_cleaned_label, 0, cleaned_count, "")
        self._animate_counter(self.space_freed_label, 0, total_freed, "bytes")
        
        self.junk_status.config(text=f"Cleanup complete: {cleaned_count} files deleted")
        
        # Clear junk files list
        self.junk_files = []
        self.clean_junk_btn.config(state="disabled")
        
        self.logger.log(f"Junk cleanup complete: {cleaned_count} files deleted, {self._format_bytes(total_freed)} freed", LogLevel.SUCCESS)
        
        messagebox.showinfo("Cleanup Complete", 
                           f"Successfully deleted {cleaned_count} junk files!\n"
                           f"Space freed: {self._format_bytes(total_freed)}")

    def cancel_junk_operation(self):
        """Cancel junk operation"""
        if self.junk_progress_handler:
            self.junk_progress_handler.is_cancelled = True
        
        self.active_operations.discard("scan_junk")
        self.active_operations.discard("clean_junk")
        self._set_junk_buttons_state()
        self.junk_animator.stop()
        self.logger.log("Junk operation cancelled", LogLevel.WARNING)

    def _set_junk_buttons_state(self, scanning: bool = False, cleaning: bool = False):
        """Manage junk cleaner button states"""
        operation_active = scanning or cleaning
        
        self.scan_junk_btn.configure(state="disabled" if operation_active else "normal")
        self.clean_junk_btn.configure(state="disabled" if operation_active or not self.junk_files else "normal")
        self.cancel_junk_btn.configure(state="normal" if operation_active else "disabled")

    def launch_tool(self, name: str, executable: str):
        """Launch system tool"""
        try:
            subprocess.Popen(executable, shell=True)
            self.logger.log(f"Launched {name}", LogLevel.INFO)
        except Exception as e:
            self.logger.log(f"Failed to launch {name}: {str(e)}", LogLevel.ERROR)
            messagebox.showerror("Error", f"Failed to launch {name}:\n{str(e)}")

    def clear_logs(self):
        """Clear the log display"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete('1.0', tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.logger.log("Logs cleared", LogLevel.INFO)

    def save_logs(self):
        """Save logs to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Logs"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get('1.0', tk.END))
                self.logger.log(f"Logs saved to {filename}", LogLevel.SUCCESS)
        except Exception as e:
            self.logger.log(f"Failed to save logs: {str(e)}", LogLevel.ERROR)

    def _format_bytes(self, bytes_count: int) -> str:
        """Format byte count into human readable format"""
        if bytes_count == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"

    def _animate_counter(self, label, start_val, end_val, value_type):
        """Set the counter value with optional animation in the future"""
        if value_type == "bytes":
            label.config(text=self._format_bytes(end_val))
        else:
            label.config(text=str(end_val))

    # ===== VIRUS SCANNER METHODS =====
    
    def _browse_scan_path(self):
        """Browse for a custom scan path"""
        path = filedialog.askdirectory(title="Select directory to scan")
        if path:
            self.custom_scan_path.set(path)

    def _update_defender_status(self):
        """Update Windows Defender status information"""
        def check_status():
            status = self.virus_scanner.get_defender_status()
            self.root.after(0, lambda: self._display_defender_status(status))
        
        threading.Thread(target=check_status, daemon=True).start()

    def _display_defender_status(self, status: Dict[str, str]):
        """Display Windows Defender status"""
        if "error" in status:
            self.defender_status_label.config(text=f"Defender Status: Error - {status['error']}", 
                                             foreground="red")
            return
            
        enabled = status.get('AntivirusEnabled', False)
        status_text = "Defender Status: Active" if enabled else "Defender Status: Inactive"
        color = "green" if enabled else "red"
        
        last_updated = status.get('AntivirusSignatureLastUpdated', 'Unknown')
        if last_updated and last_updated != 'Unknown':
            try:
                # Try to format the date
                if isinstance(last_updated, str) and len(last_updated) > 10:
                    last_updated = last_updated[:10]
            except:
                pass
        
        status_text += f" | Definitions: {last_updated}"
        
        self.defender_status_label.config(text=status_text, foreground=color)

    def start_virus_scan(self):
        """Start a virus scan"""
        if not self.virus_scanner.is_available():
            messagebox.showerror("Error", "Windows Defender not found. Virus scanning is unavailable.")
            return
            
        if "virus_scan" in self.active_operations:
            return
            
        scan_type = self.scan_type_var.get()
        
        if scan_type == "custom" and not self.custom_scan_path.get():
            messagebox.showwarning("Warning", "Please select a path for custom scan.")
            return
            
        self.active_operations.add("virus_scan")
        self._set_virus_scan_buttons_state(scanning=True)
        
        # Clear previous results
        for item in self.virus_scan_tree.get_children():
            self.virus_scan_tree.delete(item)
        
        self.virus_scan_animator.start('virus_scan', "Virus scanning")
        
        progress_handler = EnhancedProgressHandler(
            self.virus_scan_progress,
            self.virus_scan_status,
            self.virus_scan_detail
        )
        
        def update_progress(current, total, message, detail=""):
            self.root.after(0, lambda: progress_handler.update(current, total, message, detail))
        
        def on_scan_complete(future):
            try:
                scan_results = future.result()
                self.root.after(0, lambda: self._display_virus_scan_results(scan_results, progress_handler))
            except Exception as e:
                self.logger.log(f"Virus scan failed: {str(e)}", LogLevel.ERROR)
            finally:
                self.active_operations.discard("virus_scan")
                self.root.after(0, lambda: self._set_virus_scan_buttons_state(scanning=False))
        
        # Set scanner logger
        self.virus_scanner.logger = self.logger
        
        # Start the appropriate scan
        if scan_type == "quick":
            future = self.thread_pool.submit(
                self.virus_scanner.quick_scan,
                update_progress
            )
        elif scan_type == "full":
            future = self.thread_pool.submit(
                self.virus_scanner.full_scan,
                update_progress
            )
        else:  # custom
            future = self.thread_pool.submit(
                self.virus_scanner.custom_scan,
                self.custom_scan_path.get(),
                update_progress
            )
            
        future.add_done_callback(on_scan_complete)

    def _display_virus_scan_results(self, scan_results: List[VirusScanResult], 
                                  progress_handler: EnhancedProgressHandler):
        """Display virus scan results in the tree"""
        # Add items to the tree
        threats_found = 0
        for result in scan_results:
            if result.threat_name and result.threat_name != "Unknown":
                threats_found += 1
                
                # Get file name for display
                file_name = os.path.basename(result.file_path)
                if len(file_name) > 30:
                    file_name = file_name[:27] + "..."
                
                # Set severity color
                severity_color = {
                    "Severe": "🔴",
                    "High": "🟠", 
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(result.severity, "⚪")
                
                self.virus_scan_tree.insert("", "end", values=(
                    file_name,
                    result.threat_name,
                    f"{severity_color} {result.severity}",
                    result.action_taken,
                    result.file_path
                ))
        
        # Update UI
        progress_handler.reset()
        self.virus_scan_animator.stop()
        
        # Log results
        if threats_found > 0:
            self.logger.log(f"Virus scan completed: {threats_found} threats found", LogLevel.SECURITY)
            messagebox.showwarning("Scan Results", 
                                  f"Scan completed! {threats_found} threats found.\n\n"
                                  f"Please review the results and take appropriate action.")
        else:
            self.logger.log("Virus scan completed: No threats found", LogLevel.SUCCESS)
            messagebox.showinfo("Scan Results", "Scan completed! No threats found.")

    def update_defender_definitions(self):
        """Update Windows Defender virus definitions"""
        if not self.virus_scanner.is_available():
            messagebox.showerror("Error", "Windows Defender not found.")
            return
            
        self.logger.log("Updating Windows Defender definitions...", LogLevel.SECURITY)
        
        def update_defs():
            try:
                cmd = f'"{self.virus_scanner.mpcmdrun_path}" -SignatureUpdate'
                process = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                
                if process.returncode == 0:
                    self.logger.log("Defender definitions updated successfully", LogLevel.SUCCESS)
                    self.root.after(0, lambda: messagebox.showinfo("Success", 
                                                                  "Defender definitions updated successfully!"))
                else:
                    self.logger.log("Failed to update Defender definitions", LogLevel.ERROR)
                    self.root.after(0, lambda: messagebox.showerror("Error", 
                                                                   "Failed to update Defender definitions"))
                
                # Refresh status
                self._update_defender_status()
                
            except Exception as e:
                self.logger.log(f"Definition update failed: {str(e)}", LogLevel.ERROR)
                self.root.after(0, lambda: messagebox.showerror("Error", 
                                                               f"Definition update failed: {str(e)}"))
        
        threading.Thread(target=update_defs, daemon=True).start()

    def cancel_virus_scan(self):
        """Cancel the virus scan operation"""
        # Note: Windows Defender scans can't be cancelled through the command line
        # We'll just mark the operation as complete
        self.active_operations.discard("virus_scan")
        self._set_virus_scan_buttons_state(scanning=False)
        self.virus_scan_animator.stop()
        self.logger.log("Virus scan cancelled", LogLevel.WARNING)

    def _set_virus_scan_buttons_state(self, scanning: bool = False):
        """Manage virus scan button states"""
        self.start_virus_scan_btn.configure(state="disabled" if scanning else "normal")
        self.update_defender_btn.configure(state="disabled" if scanning else "normal")
        self.cancel_virus_scan_btn.configure(state="normal" if scanning else "disabled")

    def _change_theme(self, event=None):
        """Change application theme"""
        new_theme = self.theme_var.get()
        self.root.style.theme_use(new_theme)
        self.logger.log(f"Theme changed to {new_theme}", LogLevel.INFO)

    def on_close(self):
        """Handle window close with cleanup"""
        try:
            self.safe_log("Shutting down...", LogLevel.INFO)
            
            # Shutdown thread pool gracefully
            self.thread_pool.shutdown(wait=False, cancel_futures=True)
            
            # Clean up resources
            if hasattr(self, 'deep_scanner'):
                del self.deep_scanner
            
            if hasattr(self, 'virus_scanner'):
                del self.virus_scanner
            
            self.root.destroy()
        except Exception as e:
            print(f"Cleanup error: {e}")
            self.root.destroy()

# === Main Application Entry Point ===
def main():
    """Main application entry point"""
    try:
        app = EnhancedPyUninstallXPro()
        app.root.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start:\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
