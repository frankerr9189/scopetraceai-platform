#!/bin/bash
# Wrapper script for psql
export PATH="/opt/homebrew/opt/libpq/bin:$PATH"
exec /opt/homebrew/opt/libpq/bin/psql "$@"
