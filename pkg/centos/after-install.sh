/sbin/chkconfig --add gokeyless

chown -R keyless:keyless /etc/keyless

# restart the service iff it was already running
if /sbin/service gokeyless status >/dev/null 2>&1 ; then
  /sbin/service gokeyless restart >/dev/null 2>&1 || true
fi
