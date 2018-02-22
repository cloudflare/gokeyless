#!/bin/sh

chown -R keyless:keyless /etc/keyless

# restart the service iff it was already running
if service gokeyless status >/dev/null 2>&1 ; then
  service gokeyless restart >/dev/null 2>&1 || true
fi
