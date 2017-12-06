/sbin/chkconfig --add gokeyless

chown -R keyless:keyless /etc/keyless

cd /etc/keyless
# Runs interactive auto-configuration (via CF API), but only if not already
# configured.
/usr/local/bin/gokeyless -config-only
