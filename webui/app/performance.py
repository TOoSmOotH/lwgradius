import time
import functools
import logging
import sqlite3
import os
import threading
import json
from flask import request, g
from werkzeug.contrib.cache import SimpleCache
from .db_utils import get_db_connection, execute_query, optimize_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('performance')

# In-memory cache for frequently accessed data
cache = SimpleCache(threshold=500, default_timeout=300)

# Thread-local storage for performance metrics
_local = threading.local()

class PerformanceMonitor:
    """Class for monitoring and optimizing application performance"""
    
    def __init__(self):
        """Initialize the performance monitor"""
        self.slow_queries = []
        self.slow_routes = []
        self.query_counts = {}
        self.route_times = {}
        self.enabled = True
    
    def start_timer(self):
        """Start a timer for the current request"""
        _local.start_time = time.time()
        _local.queries = []
    
    def stop_timer(self):
        """Stop the timer and record metrics for the current request"""
        if not hasattr(_local, 'start_time'):
            return
        
        elapsed = time.time() - _local.start_time
        path = request.path
        
        # Record route timing
        if path in self.route_times:
            self.route_times[path].append(elapsed)
        else:
            self.route_times[path] = [elapsed]
        
        # Check if this is a slow route
        if elapsed > 0.5:  # More than 500ms is considered slow
            self.slow_routes.append({
                'path': path,
                'method': request.method,
                'time': elapsed,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'queries': getattr(_local, 'queries', [])
            })
        
        # Clean up thread local data
        if hasattr(_local, 'start_time'):
            del _local.start_time
        if hasattr(_local, 'queries'):
            del _local.queries
    
    def record_query(self, query, params, execution_time):
        """Record a database query and its execution time"""
        if not self.enabled:
            return
        
        # Normalize the query by removing extra whitespace
        normalized_query = ' '.join(query.split())
        
        # Update query counts
        if normalized_query in self.query_counts:
            self.query_counts[normalized_query]['count'] += 1
            self.query_counts[normalized_query]['total_time'] += execution_time
            self.query_counts[normalized_query]['avg_time'] = (
                self.query_counts[normalized_query]['total_time'] / 
                self.query_counts[normalized_query]['count']
            )
        else:
            self.query_counts[normalized_query] = {
                'count': 1,
                'total_time': execution_time,
                'avg_time': execution_time
            }
        
        # Check if this is a slow query
        if execution_time > 0.1:  # More than 100ms is considered slow
            slow_query = {
                'query': normalized_query,
                'params': params,
                'time': execution_time,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            self.slow_queries.append(slow_query)
            
            # Add to thread-local storage for the current request
            if hasattr(_local, 'queries'):
                _local.queries.append(slow_query)
    
    def get_slow_queries(self, limit=20):
        """Get the slowest queries"""
        return sorted(self.slow_queries, key=lambda x: x['time'], reverse=True)[:limit]
    
    def get_slow_routes(self, limit=20):
        """Get the slowest routes"""
        return sorted(self.slow_routes, key=lambda x: x['time'], reverse=True)[:limit]
    
    def get_frequent_queries(self, limit=20):
        """Get the most frequently executed queries"""
        queries = [
            {'query': query, **stats}
            for query, stats in self.query_counts.items()
        ]
        return sorted(queries, key=lambda x: x['count'], reverse=True)[:limit]
    
    def get_route_stats(self):
        """Get statistics for all routes"""
        stats = {}
        for path, times in self.route_times.items():
            avg_time = sum(times) / len(times)
            stats[path] = {
                'count': len(times),
                'avg_time': avg_time,
                'min_time': min(times),
                'max_time': max(times)
            }
        return stats
    
    def clear_metrics(self):
        """Clear all collected metrics"""
        self.slow_queries = []
        self.slow_routes = []
        self.query_counts = {}
        self.route_times = {}
    
    def generate_report(self):
        """Generate a performance report"""
        return {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'slow_queries': self.get_slow_queries(),
            'slow_routes': self.get_slow_routes(),
            'frequent_queries': self.get_frequent_queries(),
            'route_stats': self.get_route_stats()
        }
    
    def save_report(self, filename):
        """Save the performance report to a file"""
        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        return report

# Create a global instance of the performance monitor
performance_monitor = PerformanceMonitor()

def init_app(app):
    """Initialize the performance monitoring for a Flask app"""
    # Register before_request and after_request handlers
    @app.before_request
    def before_request():
        performance_monitor.start_timer()
    
    @app.after_request
    def after_request(response):
        performance_monitor.stop_timer()
        return response
    
    # Add a route for performance monitoring
    @app.route('/admin/performance', methods=['GET'])
    def performance_dashboard():
        if not g.user or g.user.role != 'admin':
            return {'error': 'Unauthorized'}, 403
        
        action = request.args.get('action')
        
        if action == 'clear':
            performance_monitor.clear_metrics()
            return {'status': 'Metrics cleared'}
        
        if action == 'optimize_db':
            result = optimize_database()
            return {'status': 'Database optimized', 'result': result}
        
        return performance_monitor.generate_report()

def monitor_query(func):
    """Decorator to monitor database query execution time"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        
        # Extract query and params from args if possible
        query = args[0] if args else 'Unknown query'
        params = args[1] if len(args) > 1 else []
        
        performance_monitor.record_query(query, params, execution_time)
        return result
    
    return wrapper

def cached(key_prefix, timeout=300):
    """
    Decorator to cache function results.
    
    Args:
        key_prefix: Prefix for the cache key
        timeout: Cache timeout in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create a cache key based on the function arguments
            key_parts = [key_prefix]
            key_parts.extend([str(arg) for arg in args])
            key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
            cache_key = ':'.join(key_parts)
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Call the function and cache the result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, timeout=timeout)
            return result
        
        return wrapper
    
    return decorator

def clear_cache(key_prefix=None):
    """
    Clear the cache.
    
    Args:
        key_prefix: If provided, only clear keys with this prefix
    """
    if key_prefix:
        # SimpleCache doesn't support partial clearing, so we'd need a more
        # sophisticated cache implementation for this
        logger.warning("Partial cache clearing not supported with SimpleCache")
    
    cache.clear()
    logger.info("Cache cleared")

def optimize_queries():
    """Analyze and optimize slow queries"""
    slow_queries = performance_monitor.get_slow_queries()
    optimizations = []
    
    for query_info in slow_queries:
        query = query_info['query']
        
        # Check for missing indexes
        if 'WHERE' in query and 'ORDER BY' in query and 'CREATE INDEX' not in query:
            # Extract table name (simple approach, might need refinement)
            table_match = re.search(r'FROM\s+(\w+)', query)
            if table_match:
                table_name = table_match.group(1)
                
                # Extract column names from WHERE clause
                where_match = re.search(r'WHERE\s+(.+?)(?:ORDER BY|GROUP BY|LIMIT|$)', query)
                if where_match:
                    where_clause = where_match.group(1)
                    columns = re.findall(r'(\w+)\s*(?:=|LIKE|>|<|>=|<=)', where_clause)
                    
                    if columns:
                        # Suggest index for these columns
                        index_name = f"idx_{table_name}_{'_'.join(columns)}"
                        create_index = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}({', '.join(columns)})"
                        
                        optimizations.append({
                            'query': query,
                            'issue': 'Missing index on WHERE clause columns',
                            'suggestion': create_index
                        })
        
        # Check for full table scans
        if 'SELECT' in query and 'WHERE' not in query and 'LIMIT' not in query:
            optimizations.append({
                'query': query,
                'issue': 'Full table scan without WHERE clause',
                'suggestion': 'Add WHERE clause or LIMIT to reduce rows scanned'
            })
        
        # Check for inefficient JOINs
        if 'JOIN' in query and 'USING' not in query and 'ON' not in query:
            optimizations.append({
                'query': query,
                'issue': 'JOIN without ON or USING clause',
                'suggestion': 'Add ON or USING clause to specify join condition'
            })
    
    return optimizations

def analyze_route_performance():
    """Analyze route performance and suggest optimizations"""
    route_stats = performance_monitor.get_route_stats()
    slow_routes = [
        {'path': path, **stats}
        for path, stats in route_stats.items()
        if stats['avg_time'] > 0.5  # Routes with avg time > 500ms
    ]
    
    return sorted(slow_routes, key=lambda x: x['avg_time'], reverse=True)

def get_memory_usage():
    """Get current memory usage"""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    return {
        'rss': memory_info.rss,  # Resident Set Size
        'rss_mb': memory_info.rss / (1024 * 1024),  # RSS in MB
        'vms': memory_info.vms,  # Virtual Memory Size
        'vms_mb': memory_info.vms / (1024 * 1024)  # VMS in MB
    }

def get_system_load():
    """Get system load information"""
    import psutil
    
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage_percent': psutil.disk_usage('/').percent
    }

def optimize_app_performance():
    """Run all performance optimizations"""
    # Optimize database
    db_result = optimize_database()
    
    # Analyze and optimize queries
    query_optimizations = optimize_queries()
    
    # Analyze route performance
    slow_routes = analyze_route_performance()
    
    # Get system metrics
    memory_usage = get_memory_usage()
    system_load = get_system_load()
    
    return {
        'database_optimization': db_result,
        'query_optimizations': query_optimizations,
        'slow_routes': slow_routes,
        'memory_usage': memory_usage,
        'system_load': system_load,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }

# Monkey patch sqlite3.Connection.execute to monitor queries
original_execute = sqlite3.Connection.execute

def patched_execute(self, sql, parameters=None):
    """Patched version of sqlite3.Connection.execute that monitors query performance"""
    start_time = time.time()
    
    if parameters is None:
        result = original_execute(self, sql)
    else:
        result = original_execute(self, sql, parameters)
    
    execution_time = time.time() - start_time
    performance_monitor.record_query(sql, parameters, execution_time)
    
    return result

# Apply the monkey patch
sqlite3.Connection.execute = patched_execute