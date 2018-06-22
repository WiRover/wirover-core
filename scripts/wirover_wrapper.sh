#!/bin/sh
#
# Use this wrapper script to call any of the WiRover modules.  It makes sure
# certain required files exist before running the command.
#
# Example:
# wirover_wrapper.sh wicontroller
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
    sha1sum node.pub | grep -oE '^([0-9a-f]+)' >node_id

    chmod 400 node.key
    chmod 444 node.pub
    chmod 444 node_id
fi

touch "$WIROVER_VAR_DIR"/path_list
touch "$WIROVER_VAR_DIR"/path_pred

date > $WIROVER_VAR_DIR/installed

update_config() {
    variable=$1
    value=$2
    for ftype in wicontroller wigateway wiroot; do
        if [ -f "/etc/$ftype.conf" ]; then
            sed "s/$variable = .*/$variable = \"$value\";/" -i /etc/$ftype.conf
        fi
    done
}

if [ -n "$WIROVER_WIROOT_ADDRESS" ]; then
    update_config "wiroot-address" "$WIROVER_WIROOT_ADDRESS"
fi

$@
