#!/bin/sh
# Wrapper for uacme to work on openwrt.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
#
# Initial Author: Toke Høiland-Jørgensen <toke@toke.dk>
# Adapted for uacme: Lucian Cristian <lucian.cristian@gmail.com>

CHECK_CRON=$1
ACME=/usr/sbin/uacme
HPROGRAM=/usr/share/uacme/uacme.sh
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export NO_TIMESTAMP=1

UHTTPD_LISTEN_HTTP=
STATE_DIR='/etc/acme'
ACCOUNT_EMAIL=
DEBUG=0
NGINX_WEBSERVER=0
UPDATE_NGINX=0
UPDATE_UHTTPD=0

. /lib/functions.sh

check_cron()
{
    [ -f "/etc/crontabs/root" ] && grep -q '/etc/init.d/acme' /etc/crontabs/root && return
    echo "0 0 * * * /etc/init.d/acme start" >> /etc/crontabs/root
    /etc/init.d/cron start
}

log()
{
    logger -t uacme -s -p daemon.info "$@"
}

err()
{
    logger -t uacme -s -p daemon.err "$@"
}

debug()
{
    [ "$DEBUG" -eq "1" ] && logger -t uacme -s -p daemon.debug "$@"
}

get_listeners() {
    local proto rq sq listen remote state program
    netstat -nptl 2>/dev/null | while read proto rq sq listen remote state program; do
        case "$proto#$listen#$program" in
            tcp#*:80#[0-9]*/*) echo -n "${program%% *} " ;;
        esac
    done
}

pre_checks()
{
    main_domain="$1"

    log "Running pre checks for $main_domain."

    listeners="$(get_listeners)"

    debug "port80 listens: $listeners"

    for listener in $(get_listeners); do
	pid="${listener%/*}"
	cmd="${listener#*/}"

	case "$cmd" in
	    uhttpd)
		debug "Found uhttpd listening on port 80"
	    ;;
	    nginx*)
		debug "Found nginx listening on port 80"
		NGINX_WEBSERVER=1
            ;;
	    "")
		err "Nothing listening on port 80."
		err "Standalone mode not supported, setup uhttpd or nginx"
		return 1
            ;;
            *)
		err "$main_domain: unsupported (apache?) daemon is listening on port 80."
		err "if webroot is setup on your webserver comment line 89 (return 1) from this script."
		return 1
            ;;
	esac
    done

    iptables -I input_rule -p tcp --dport 80 -j ACCEPT -m comment --comment "ACME" || return 1
    ip6tables -I input_rule -p tcp --dport 80 -j ACCEPT -m comment --comment "ACME" || return 1
    debug "v4 input_rule: $(iptables -nvL input_rule)"
    debug "v6 input_rule: $(ip6tables -nvL input_rule)"
    return 0
}

post_checks()
{
    log "Running post checks (cleanup)."
    # The comment ensures we only touch our own rules. If no rules exist, that
    # is fine, so hide any errors
    iptables -D input_rule -p tcp --dport 80 -j ACCEPT -m comment --comment "ACME" 2>/dev/null
    ip6tables -D input_rule -p tcp --dport 80 -j ACCEPT -m comment --comment "ACME" 2>/dev/null

    if [ -e /etc/init.d/uhttpd ] && [ "$UPDATE_UHTTPD" -eq 1 ]; then
	uci commit uhttpd
	/etc/init.d/uhttpd reload
    fi

    if [ -e /etc/init.d/nginx ] && ( [ "$NGINX_WEBSERVER" -eq 1 ] || [ "$UPDATE_NGINX" -eq 1 ] ); then
	NGINX_WEBSERVER=0
	/etc/init.d/nginx restart
    fi
}

err_out()
{
    post_checks
    exit 1
}

int_out()
{
    post_checks
    trap - INT
    kill -INT $$
}

is_staging()
{
#needs a way to determine it
    local main_domain="$1"

    grep -q "acme-staging" "$STATE_DIR/$main_domain/${main_domain}.conf"
    return $?
}

issue_cert()
{
    local section="$1"
    local acme_args=
    local enabled
    local use_staging
    local update_uhttpd
    local update_nginx
    local keylength
    local domains
    local main_domain
    local moved_staging=0
    local failed_dir
    local webroot
    local dns
    local ret

    config_get_bool enabled "$section" enabled 0
    config_get_bool use_staging "$section" use_staging
    config_get_bool update_uhttpd "$section" update_uhttpd
    config_get_bool update_nginx "$section" update_nginx
    config_get domains "$section" domains
    config_get keylength "$section" keylength
    config_get webroot "$section" webroot
    config_get dns "$section" dns

    UPDATE_NGINX=$update_nginx
    UPDATE_UHTTPD=$update_uhttpd

    [ "$enabled" -eq "1" ] || return

    [ "$DEBUG" -eq "1" ] && acme_args="$acme_args --verbose --verbose"

    set -- $domains
    main_domain=$1

    [ -n "$webroot" ] || [ -n "$dns" ] || pre_checks "$main_domain" || return 1

    log "Running uACME for $main_domain"

#    handle_credentials() {
#        local credential="$1"
#        eval export $credential
#    }
#    config_list_foreach "$section" credentials handle_credentials

    if [ ! -f  "$STATE_DIR/private/key.pem" ]; then
	log "Create a new ACME account with email $ACCOUNT_EMAIL"
	$ACME --confdir "$STATE_DIR" --yes new $ACCOUNT_EMAIL
    fi

    if [ -f "$STATE_DIR/private/$main_domain/key.pem" ]; then
#TO-DO
#        if [ "$use_staging" -eq "0" ] && is_staging "$main_domain"; then
#            log "Found previous cert issued using staging server. Moving it out of the way."
#            mv "$STATE_DIR/$main_domain" "$STATE_DIR/$main_domain.staging"
#            moved_staging=1
#        else
            log "Found previous cert config. Issuing renew."
            $ACME --confdir "$STATE_DIR" --never-create issue "$main_domain" $acme_args -hook=$HPROGRAM && ret=0 || ret=1
            post_checks
            return $ret
#        fi
    fi


    uacme_args="$uacme_args --bits $keylength"
    [ "$use_staging" -eq "1" ] && uacme_args="$uacme_args --staging"
    uacme_args="$uacme_args $(for d in $domains; do echo -n " $d "; done)"
#    [ -n "$ACCOUNT_EMAIL" ] && uacme_args="$uacme_args $ACCOUNT_EMAIL"

    if [ -n "$dns" ]; then
#TO-DO
        log "Using dns mode dns-01 is not ready yet"
#        uacme_args="$uacme_args --dns $dns"
    else
        if [ ! -d "$webroot" ]; then
            err "$main_domain: Webroot dir '$webroot' does not exist!"
            post_checks
            return 1
        fi
#TO-DO
        log "Using webroot dir: $webroot, (hardcoded in the script for the moment)"
#        uacme_args="$uacme_args --webroot $webroot"
    fi

    if ! $ACME --confdir "$STATE_DIR" $acme_args issue $uacme_args -hook=$HPROGRAM; then
        failed_dir="$STATE_DIR/${main_domain}.failed-$(date +%s)"
        err "Issuing cert for $main_domain failed. Moving state to $failed_dir"
        [ -d "$STATE_DIR/$main_domain" ] && mv "$STATE_DIR/$main_domain" "$failed_dir"
        if [ "$moved_staging" -eq "1" ]; then
            err "Restoring staging certificate"
            mv "$STATE_DIR/${main_domain}.staging" "$STATE_DIR/${main_domain}"
        fi
        post_checks
        return 1
    fi

    if [ -e /etc/init.d/uhttpd ] && [ "$update_uhttpd" -eq "1" ]; then
        uci set uhttpd.main.key="$STATE_DIR/private/${main_domain}/key.pem"
        uci set uhttpd.main.cert="$STATE_DIR/${main_domain}/cert.pem"
        # commit and reload is in post_checks
    fi

    if [ -e /etc/init.d/nginx ] && [ "$update_nginx" -eq "1" ]; then
        sed -i "s#ssl_certificate\ .*#ssl_certificate $STATE_DIR/${main_domain}/cert.pem;#g" /etc/nginx/nginx.conf
        sed -i "s#ssl_certificate_key\ .*#ssl_certificate_key $STATE_DIR/private/${main_domain}/key.pem;#g" /etc/nginx/nginx.conf
        # commit and reload is in post_checks
    fi

    post_checks
}

load_vars()
{
    local section="$1"

    STATE_DIR=$(config_get "$section" state_dir)
    ACCOUNT_EMAIL=$(config_get "$section" account_email)
    DEBUG=$(config_get "$section" debug)
}

check_cron
[ -n "$CHECK_CRON" ] && exit 0
[ -e "/var/run/uacme_boot" ] && rm -f "/var/run/uacme_boot" && exit 0

config_load acme
config_foreach load_vars acme

if [ -z "$STATE_DIR" ] || [ -z "$ACCOUNT_EMAIL" ]; then
    err "state_dir and account_email must be set"
    exit 1
fi

[ -d "$STATE_DIR" ] || mkdir -p "$STATE_DIR"

trap err_out HUP TERM
trap int_out INT

config_foreach issue_cert cert

exit 0
