#!/bin/sh
# Start Zeek on the probe's mirror port.
#
# Zeek empties (truncates) its log files when it starts. To never lose lines that
# Module 4 has not read yet, first move the previous run's logs into
# archive/<unix-time>/. Module 4 reads that archive folder too.
#
# Used by probe1 and probe2 in enterprise.clab.yml (bind-mounted to /start-zeek.sh).
set -eu

iface="${ZEEK_IFACE:-eth1}"
cd /opt/zeek/logs

# Never start a second Zeek (the image has no pgrep, so look in /proc).
for c in /proc/[0-9]*/comm; do
    if [ "$(cat "$c" 2>/dev/null)" = "zeek" ]; then
        echo "zeek is already running, nothing to do"
        exit 0
    fi
done

if ls ./*.log >/dev/null 2>&1; then
    dir="archive/$(date +%s)"
    mkdir -p "$dir"
    mv ./*.log "$dir"/
fi

# The policy scripts feed SSH banners and HTTP response headers into Zeek's
# built-in software framework, which writes software.log alongside the base logs.
zeek -i "$iface" LogAscii::use_json=T \
    policy/protocols/ssh/software \
    policy/protocols/http/software >zeek.out 2>&1 &
