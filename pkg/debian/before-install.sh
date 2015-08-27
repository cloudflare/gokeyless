#!/bin/sh

# create logstash group
if ! getent group keyless >/dev/null; then
  groupadd -r keyless
fi

# create logstash user
if ! getent passwd keyless >/dev/null; then
  useradd -M -r -g keyless \
    -s /sbin/nologin -c "CloudFlare Keyless Service User" keyless
fi
