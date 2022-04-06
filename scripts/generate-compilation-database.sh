#!/usr/bin/env bash

echo "["

first="true"

for source in $(ls bpf/*.c); do
  if [[ "${first}" == "true" ]]; then
    first="false"
  else
    echo ","
  fi
  echo "  {"
  echo "    \"file\": \"${source}\","
  echo "    \"command\": \"${CC} ${CFLAGS} ${MACROS} -c ${source}\","
  echo "    \"directory\": \"$(pwd)\""
  echo -n "  }"
done

echo
echo "]"
