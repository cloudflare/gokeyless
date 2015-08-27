if [ $1 -eq 0 ]; then
  /sbin/service gokeyless stop >/dev/null 2>&1 || true
  /sbin/chkconfig --del gokeyless
  if getent passwd keyless >/dev/null ; then
    userdel keyless
  fi

  if getent group keyless >/dev/null ; then
    groupdel keyless
  fi
fi
