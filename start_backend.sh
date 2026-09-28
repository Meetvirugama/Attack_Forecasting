#!/bin/bash
# CyberLens Backend Launcher
# Fixes macOS OpenMP conflict caused by a1_coverage.pth running before KMP env var is set
# Uses -S to skip site.py, then manually adds site-packages
exec python3 -S -c "
import sys
sys.path.insert(0, '/opt/homebrew/lib/python3.14/site-packages')
sys.path.insert(0, '$(cd "$(dirname "$0")" && pwd)')
import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

# Re-enable usersite manually
import site
site.addsitedir('/opt/homebrew/lib/python3.14/site-packages')

# Now import and run api
import backend.api
backend.api.start(8000)
" 2>&1
