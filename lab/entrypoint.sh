#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Lab mail server entrypoint.
#   configure  (at image build) applies the Postfix settings with postconf and installs dovecot.conf
#   run        (at start) picks the Dovecot profile named by LAB_PROFILE, starts Dovecot, then Postfix
set -eu

configure() {
  cp /etc/dovecot/lab/dovecot.conf /etc/dovecot/dovecot.conf
  postconf -e \
    'compatibility_level = 3.10' \
    'myhostname = localhost' \
    'mydomain = example.test' \
    'mydestination =' \
    'inet_interfaces = all' \
    'inet_protocols = ipv4' \
    'maillog_file = /dev/stdout' \
    'virtual_mailbox_domains = example.test, example.org' \
    'virtual_mailbox_maps = texthash:/etc/postfix/lab/vmailbox' \
    'virtual_transport = lmtp:unix:private/dovecot-lmtp' \
    'message_size_limit = 26214400' \
    'smtputf8_enable = yes' \
    'smtpd_tls_chain_files = /lab/tls/server.key, /lab/tls/server.pem' \
    'smtpd_tls_security_level = may' \
    'smtpd_tls_auth_only = yes' \
    'smtpd_tls_mandatory_protocols = >=TLSv1.2' \
    'smtpd_sasl_type = dovecot' \
    'smtpd_sasl_path = private/auth' \
    'smtpd_sender_login_maps = texthash:/etc/postfix/lab/sender_login'
  # Submission ports: 587 refuses everything until STARTTLS (security level encrypt); 465 is implicit TLS.
  # Both require SASL and refuse an envelope sender the signed-in mailbox does not own.
  for svc in submission submissions; do
    postconf -M "$svc/inet=$svc inet n - n - - smtpd"
    postconf -P \
      "$svc/inet/syslog_name=postfix/$svc" \
      "$svc/inet/smtpd_sasl_auth_enable=yes" \
      "$svc/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject" \
      "$svc/inet/smtpd_sender_restrictions=reject_sender_login_mismatch" \
      "$svc/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject" \
      "$svc/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"
  done
  postconf -P 'submission/inet/smtpd_tls_security_level=encrypt' 'submissions/inet/smtpd_tls_wrappermode=yes'
}

run() {
  profile="${LAB_PROFILE:-flat}"
  if [ ! -f "/etc/dovecot/lab/profile-$profile.conf" ]; then
    echo "unknown LAB_PROFILE $profile" >&2; exit 2
  fi
  cp "/etc/dovecot/lab/profile-$profile.conf" /etc/dovecot/lab/active-profile.conf
  # Dovecot puts its auth and LMTP sockets in Postfix's private directory, so it must exist first.
  install -d -o postfix -g root -m 0700 /var/spool/postfix/private
  dovecot
  exec postfix start-fg
}

case "${1:-run}" in
  configure) configure ;;
  run) run ;;
  *) exec "$@" ;;
esac
