#!/usr/bin/env python3
"""
Performance Optimization Script for FreeRADIUS TOTP Management System

This script runs a series of performance optimizations on the application
to improve database performance, optimize queries, and enhance overall system performance.
"""

import os
import sys
import argparse
import json
import logging
from datetime import datetime

# Add the parent directory to the path so we can import the app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.db_utils import (
    optimize_database, check_database_integrity, 
    get_database_stats, create_backup
)
from app.performance import (
    optimize_queries, analyze_route_performance,
    optimize_app_performance, clear_cache
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('performance_optimization')

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Run performance optimizations on the FreeRADIUS TOTP Management System')
    
    parser.add_argument('--backup', action='store_true',
                        help='Create a database backup before optimizing')
    
    parser.add_argument('--backup-path', default=None,
                        help='Path to save the database backup (default: auto-generated)')
    
    parser.add_argument('--output', default=None,
                        help='Path to save the optimization report (default: performance_report_TIMESTAMP.json)')
    
    parser.add_argument('--optimizations', default='all',
                        help='Comma-separated list of optimizations to run (default: all)')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Generate output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f'performance_report_{timestamp}.json'
    
    # Print optimization configuration
    logger.info('Starting performance optimizations with the following configuration:')
    logger.info(f'Create Backup: {args.backup}')
    if args.backup:
        logger.info(f'Backup Path: {args.backup_path or "auto-generated"}')
    logger.info(f'Output File: {args.output}')
    
    # Create database backup if requested
    if args.backup:
        logger.info('Creating database backup...')
        backup_path = create_backup(args.backup_path)
        if backup_path:
            logger.info(f'Database backup created at: {backup_path}')
        else:
            logger.error('Failed to create database backup')
            return 1
    
    # Determine which optimizations to run
    if args.optimizations.lower() == 'all':
        optimizations_to_run = [
            'database',
            'queries',
            'routes',
            'cache'
        ]
    else:
        optimizations_to_run = [opt.strip() for opt in args.optimizations.split(',')]
    
    logger.info(f'Running the following optimizations: {", ".join(optimizations_to_run)}')
    
    # Initialize results dictionary
    results = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'optimizations': {}
    }
    
    # Run optimizations
    for optimization in optimizations_to_run:
        logger.info(f'Running {optimization} optimization...')
        
        if optimization == 'database':
            # Check database integrity
            integrity_result = check_database_integrity()
            logger.info(f'Database integrity check: {integrity_result["integrity_check"]}')
            
            # Get database stats before optimization
            before_stats = get_database_stats()
            logger.info(f'Database size before optimization: {before_stats["size_mb"]} MB')
            
            # Optimize database
            db_result = optimize_database()
            logger.info(f'Database optimization completed: {db_result}')
            
            # Get database stats after optimization
            after_stats = get_database_stats()
            logger.info(f'Database size after optimization: {after_stats["size_mb"]} MB')
            
            # Calculate size reduction
            size_reduction = before_stats["size_mb"] - after_stats["size_mb"]
            size_reduction_percent = (size_reduction / before_stats["size_mb"]) * 100 if before_stats["size_mb"] > 0 else 0
            
            logger.info(f'Size reduction: {size_reduction:.2f} MB ({size_reduction_percent:.2f}%)')
            
            # Add results to dictionary
            results['optimizations']['database'] = {
                'before': before_stats,
                'after': after_stats,
                'integrity': integrity_result,
                'optimization': db_result,
                'size_reduction_mb': size_reduction,
                'size_reduction_percent': size_reduction_percent
            }
        
        elif optimization == 'queries':
            # Optimize queries
            query_optimizations = optimize_queries()
            logger.info(f'Query optimizations: {len(query_optimizations)} suggestions')
            
            # Add results to dictionary
            results['optimizations']['queries'] = query_optimizations
        
        elif optimization == 'routes':
            # Analyze route performance
            slow_routes = analyze_route_performance()
            logger.info(f'Slow routes identified: {len(slow_routes)}')
            
            # Add results to dictionary
            results['optimizations']['routes'] = slow_routes
        
        elif optimization == 'cache':
            # Clear cache
            logger.info('Clearing application cache...')
            clear_cache()
            logger.info('Cache cleared successfully')
            
            # Add results to dictionary
            results['optimizations']['cache'] = {
                'cleared': True,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        
        else:
            logger.warning(f'Unknown optimization: {optimization}')
    
    # Run comprehensive optimization if all optimizations are selected
    if set(optimizations_to_run) == set(['database', 'queries', 'routes', 'cache']):
        logger.info('Running comprehensive optimization...')
        comprehensive_results = optimize_app_performance()
        results['comprehensive'] = comprehensive_results
    
    # Save results to file
    logger.info(f'Saving optimization report to {args.output}...')
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info('Performance optimizations completed successfully!')
    return 0

if __name__ == '__main__':
    sys.exit(main())