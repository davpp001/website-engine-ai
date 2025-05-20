#!/bin/bash
# Cronjob für wöchentlichen Snapshot
/usr/bin/env python3 /usr/local/bin/ionos_wp_manager.py snapshot
