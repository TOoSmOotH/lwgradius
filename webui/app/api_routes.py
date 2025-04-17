from flask import Blueprint, jsonify, request, current_app
from datetime import datetime
import sqlite3
import os
import json
import time

api_bp = Blueprint('api', __name__)

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint that doesn't require authentication"""
    # Check if we can connect to the database
    db_healthy = True
    db_error = None
    
    try:
        conn = sqlite3.connect(current_app.config['SQLITE_DB'])
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
    except Exception as e:
        db_healthy = False
        db_error = str(e)
    
    # Check if FreeRADIUS is accessible
    radius_healthy = True
    radius_error = None
    
    # Simple check - just verify the database has the radcheck table
    # A more comprehensive check would actually test RADIUS authentication
    try:
        conn = sqlite3.connect(current_app.config['SQLITE_DB'])
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='radcheck'")
        if not cursor.fetchone():
            radius_healthy = False
            radius_error = "radcheck table not found in database"
        conn.close()
    except Exception as e:
        radius_healthy = False
        radius_error = str(e)
    
    # Get system metrics
    system_metrics = {
        "cpu_usage": get_cpu_usage(),
        "memory_usage": get_memory_usage(),
        "disk_usage": get_disk_usage(),
        "uptime": get_uptime()
    }
    
    response = {
        "status": "healthy" if db_healthy and radius_healthy else "unhealthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "components": {
            "database": {
                "status": "healthy" if db_healthy else "unhealthy",
                "error": db_error
            },
            "radius": {
                "status": "healthy" if radius_healthy else "unhealthy",
                "error": radius_error
            }
        },
        "system": system_metrics
    }
    
    status_code = 200 if response["status"] == "healthy" else 503
    return jsonify(response), status_code

def get_cpu_usage():
    """Get CPU usage percentage"""
    try:
        # Simple implementation using /proc/stat
        # For a more accurate measurement, use psutil in a production environment
        with open('/proc/stat', 'r') as f:
            cpu = f.readline().split()
        
        user = float(cpu[1])
        nice = float(cpu[2])
        system = float(cpu[3])
        idle = float(cpu[4])
        
        total = user + nice + system + idle
        usage = 100 * (1 - (idle / total))
        
        return round(usage, 2)
    except Exception:
        return None

def get_memory_usage():
    """Get memory usage percentage"""
    try:
        # Simple implementation using /proc/meminfo
        # For a more accurate measurement, use psutil in a production environment
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
        
        mem_info = {}
        for line in lines:
            key, value = line.split(':', 1)
            mem_info[key.strip()] = int(value.strip().split()[0])
        
        total = mem_info.get('MemTotal', 0)
        free = mem_info.get('MemFree', 0)
        buffers = mem_info.get('Buffers', 0)
        cached = mem_info.get('Cached', 0)
        
        used = total - free - buffers - cached
        usage = 100 * (used / total) if total > 0 else 0
        
        return round(usage, 2)
    except Exception:
        return None

def get_disk_usage():
    """Get disk usage percentage for the data directory"""
    try:
        # Simple implementation using os.statvfs
        # For a more accurate measurement, use psutil in a production environment
        data_dir = os.path.dirname(current_app.config['SQLITE_DB'])
        stat = os.statvfs(data_dir)
        
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        usage = 100 * (used / total) if total > 0 else 0
        
        return round(usage, 2)
    except Exception:
        return None

def get_uptime():
    """Get system uptime in seconds"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        return round(uptime_seconds)
    except Exception:
        return None

# Additional API endpoints will be added here