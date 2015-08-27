# create keyless group
if ! getent group keyless >/dev/null; then
  groupadd -r keyless
fi

# create keyless user
if ! getent passwd keyless >/dev/null; then
  useradd -r -g keyless \
    -s /sbin/nologin -c "CloudFlare Keyless Service User" keyless
fi
