#!/bin/sh

if [ $1 = "remove" ]; then
  service gokeyless stop >/dev/null 2>&1 || true

  if getent passwd keyless >/dev/null ; then
    userdel keyless
  fi

  if getent group keyless >/dev/null ; then
    groupdel keyless
  fi
fi
