#!/bin/bash
#
# This script does some one-time jobs to complete the gateway installation.
#

WIROVER_BIN_DIR=/usr/bin
WIROVER_LOG_DIR=/var/log
WIROVER_VAR_DIR=/var/lib/wirover

test -d "$WIROVER_LOG_DIR" || mkdir "$WIROVER_LOG_DIR"
test -d "$WIROVER_VAR_DIR" || mkdir "$WIROVER_VAR_DIR"

if [ ! -f /etc/wirover.d/node.key ]; then
    mkdir -p /etc/wirover.d

    cd /etc/wirover.d
    openssl genrsa -out node.key 2048
    openssl rsa -in node.key -pubout -out node.pub
    sha1sum node.pub | perl -n -e 'chomp; print $1 if /^([0-9a-f]+)/' >node_id

    chmod 400 node.key
    chmod 444 node.pub
    chmod 444 node_id
fi

touch "$WIROVER_VAR_DIR"/path_list
touch "$WIROVER_VAR_DIR"/path_pred
chown -R wirover "$WIROVER_VAR_DIR"

date > $WIROVER_VAR_DIR/installed


