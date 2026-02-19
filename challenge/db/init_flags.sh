#!/bin/bash
# Inject the Credential Harvester flag as a username in the users table.
# This runs after 01_bankingai.sql during DB initialisation.
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}" \
  -e "UPDATE users SET username = '${FLAG_CREDENTIAL_HARVESTER}' WHERE id = 22;"
