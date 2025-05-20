#!/bin/bash
# Cronjob für automatisches Backup
/usr/bin/env python3 /usr/local/bin/ionos_wp_manager.py backup --auto
