# Ansible Role: postfix

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-postfix)
![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-role-postfix)
![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-role-postfix)
[![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-postfix/dev.yml?branch=dev&label=dev)](https://github.com/jomrr/ansible-role-postfix/actions/workflows/dev.yml?query=branch%3Adev)
[![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-postfix/main.yml?branch=main&label=main)](https://github.com/jomrr/ansible-role-postfix/actions/workflows/main.yml?query=branch%3Amain)

Configure Postfix listeners, delivery routes, sender authorization and file, SQL
or LDAP lookup tables.

## Purpose

Install and operate Postfix with independent SMTP listeners and delivery
routes. Select a starting point from the operating modes below.

| Operating mode | Listener policy | Outbound route |
| --- | --- | --- |
| Local mail only (default) | None | none |
| Internal mail hub | Authenticated, local destinations | none |
| Submission with SQL or AD | TLS and SASL | direct or relayhost |
| Trusted application relay | Explicit client networks | direct |
| Null client | None | relayhost |
| Public MX or gateway | Public, destination restricted | direct |

## Scope

### Managed

- Postfix packages, service state, listeners, outbound transports, local and
  virtual mail, gateway recipients and aliases.
- Per-listener authentication, sender ownership, client networks, Milter and
  policy services, postscreen and optional DNSBLs.
- File, PostfixAdmin SQL and TLS-verified LDAP lookups, indexed access tables,
  archive copies and queue retry settings.

### Not Managed

- SASL authentication services, directory accounts, database schemas, Fetchmail,
  DNS records and external Milters or policy daemons.
- Certificate issuance, DANE DNSSEC validation infrastructure and MTA-STS policy
  services.

## Requirements

- Postfix 3.6 or later. Network listeners require a build with
  smtpd_forbid_unauth_pipelining. The normalize and reject newline policies also
  require a package with the corresponding security update.
- For authenticated listeners, provide a PEM chain and key and either a Dovecot
  auth socket or a working Cyrus SASL application configuration.
- For virtual delivery, the LMTP backend must recognize the same recipients.
  Secure TCP LMTP requires a certificate for the configured next hop.
- SQL uses the PostfixAdmin domain, mailbox, alias and alias_domain tables with
  a SELECT-only login. Verified LDAPS requires a readable PEM CA file.

## Dependencies

```yaml
collections:
  - name: community.general
    version: '>=12.0.0'
```

## Role Variables

### `postfix_hostname`

Type: `str`. Required: `false`.

Fully qualified hostname announced by the mail server. Defaults to the host
FQDN.

### `postfix_origin`

Type: `str`. Required: `false`.

Domain appended to locally submitted unqualified addresses.

Default:

```yaml
postfix_origin: $myhostname
```

### `postfix_interfaces`

Type: `list`. Required: `false`.

Global listening interfaces for services without an explicit bind address.

Default:

```yaml
postfix_interfaces:
  - loopback-only
```

### `postfix_protocols`

Type: `str`. Required: `false`.

IP protocol families enabled by Postfix.

Default:

```yaml
postfix_protocols: all
```

### `postfix_local_domains`

Type: `list`. Required: `false`.

Domains delivered to local Unix accounts through the local delivery agent.

Default:

```yaml
postfix_local_domains:
  - $myhostname
  - localhost.$mydomain
  - localhost
```

### `postfix_trusted_networks`

Type: `list`. Required: `false`.

Global trusted networks used by native Postfix parameters. Network relay
requires explicit listener clients.

Default:

```yaml
postfix_trusted_networks:
  - 127.0.0.0/8
  - '[::1]/128'
```

### `postfix_local_aliases`

Type: `dict`. Required: `false`.

Local delivery aliases, including an optional root alias for a monitored address
or local mailbox.

Default:

```yaml
postfix_local_aliases:
  postmaster: root
  mailer-daemon: postmaster
  abuse: postmaster
```

### `postfix_dovecot_auth_socket`

Type: `str`. Required: `false`.

Dovecot authentication socket relative to the Postfix queue directory.

Default:

```yaml
postfix_dovecot_auth_socket: private/auth
```

### `postfix_tls_certificate`

Type: `str`. Required: `false`.

PEM certificate chain for listeners that provide or require TLS.

Default:

```yaml
postfix_tls_certificate: ''
```

### `postfix_tls_private_key`

Type: `str`. Required: `false`.

PEM private key matching the certificate chain for TLS-enabled listeners.

Default:

```yaml
postfix_tls_private_key: ''
```

### `postfix_tls_ca_file`

Type: `str`. Required: `false`.

Additional trusted CA bundle for outgoing TLS. An empty value selects the
platform bundle.

Default:

```yaml
postfix_tls_ca_file: ''
```

### `postfix_local_submitters`

Type: `dict`. Required: `false`.

Unix submitters and their permitted envelope senders. By default, root may use
any sender address.

Default:

```yaml
postfix_local_submitters:
  root:
    - '*'
```

### `postfix_account_backend`

Type: `str`. Required: `false`.

Primary lookup backend for recipients, aliases and sender ownership.

Default:

```yaml
postfix_account_backend: files
```

### `postfix_ldap_enabled`

Type: `bool`. Required: `false`.

Enables TLS-verified LDAP mailbox and sender lookups alongside the primary
backend.

Default:

```yaml
postfix_ldap_enabled: false
```

### `postfix_ldap`

Type: `dict`. Required: `false`.

Read-only LDAPS connection, directory eligibility filter and attributes
identifying a mailbox and its SASL owner.

Default:

```yaml
postfix_ldap:
  uris: []
  base: ''
  bind_dn: ''
  bind_password: ''
  ca_file: ''
  eligibility_filter: ''
  mail_attribute: mail
  login_attribute: userPrincipalName
```

### `postfix_sasl_access_enabled`

Type: `bool`. Required: `false`.

Requires a positive SASL login access lookup on every listener requiring SMTP
AUTH. The default permits authenticated clients.

Default:

```yaml
postfix_sasl_access_enabled: false
```

### `postfix_sasl_access_logins`

Type: `list`. Required: `false`.

Explicitly entitled SASL logins, including file-based relay accounts, checked
before LDAP when the access check is enabled.

Default:

```yaml
postfix_sasl_access_logins: []
```

### `postfix_mailboxes`

Type: `list`. Required: `false`.

Virtual mailbox addresses from files, available alongside SQL and LDAP.

Default:

```yaml
postfix_mailboxes: []
```

### `postfix_virtual_aliases`

Type: `dict`. Required: `false`.

Local virtual aliases and their destinations, searched before SQL and LDAP.

Default:

```yaml
postfix_virtual_aliases: {}
```

### `postfix_sender_logins`

Type: `dict`. Required: `false`.

Local envelope sender owners, searched before SQL and LDAP.

Default:

```yaml
postfix_sender_logins: {}
```

### `postfix_dovecot_lmtp_transport`

Type: `str`. Required: `false`.

LMTP destination used for virtual mailbox delivery to Dovecot.

Default:

```yaml
postfix_dovecot_lmtp_transport: lmtp:unix:private/dovecot-lmtp
```

### `postfix_local_lmtp_enabled`

Type: `bool`. Required: `false`.

Enables Dovecot LMTP delivery for local Unix recipients.

Default:

```yaml
postfix_local_lmtp_enabled: false
```

### `postfix_providers`

Type: `list`. Required: `false`.

Named external providers with separate credentials and TLS transports.

Default:

```yaml
postfix_providers: []
```

### `postfix_provider_port`

Type: `int`. Required: `false`.

Default external provider port, with optional per-provider overrides.

Default:

```yaml
postfix_provider_port: 587
```

### `postfix_provider_tls`

Type: `str`. Required: `false`.

Default external provider TLS mode, with optional per-provider overrides.

Default:

```yaml
postfix_provider_tls: starttls
```

### `postfix_default_provider`

Type: `str`. Required: `false`.

Optional default named provider for unmatched senders in direct mode.

Default:

```yaml
postfix_default_provider: ''
```

### `postfix_sender_relays`

Type: `dict`. Required: `false`.

Exact envelope sender addresses mapped to provider names.

Default:

```yaml
postfix_sender_relays: {}
```

### `postfix_transport_maps`

Type: `dict`. Required: `false`.

Additional recipient domain or address transport routes.

Default:

```yaml
postfix_transport_maps: {}
```

### `postfix_tls_policies`

Type: `dict`. Required: `false`.

SMTP next-hop destinations mapped to TLS security policies and optional
certificate matching attributes.

Default:

```yaml
postfix_tls_policies: {}
```

### `postfix_sender_bcc`

Type: `dict`. Required: `false`.

Envelope senders and their optional outgoing archive copy address.

Default:

```yaml
postfix_sender_bcc: {}
```

### `postfix_recipient_bcc`

Type: `dict`. Required: `false`.

Envelope recipients and their optional incoming archive copy address.

Default:

```yaml
postfix_recipient_bcc: {}
```

### `postfix_message_size_limit`

Type: `int`. Required: `false`.

Maximum accepted message size in bytes.

Default:

```yaml
postfix_message_size_limit: 10240000
```

### `postfix_mailbox_size_limit`

Type: `int`. Required: `false`.

Maximum size of a local mailbox or maildir file in bytes. Zero allows unlimited
size. A positive limit must be at least postfix_message_size_limit.

Default:

```yaml
postfix_mailbox_size_limit: 51200000
```

### `postfix_maximal_queue_lifetime`

Type: `str`. Required: `false`.

Maximum time that undelivered messages remain queued.

Default:

```yaml
postfix_maximal_queue_lifetime: 5d
```

### `postfix_bounce_queue_lifetime`

Type: `str`. Required: `false`.

Maximum time that undeliverable bounce messages remain queued.

Default:

```yaml
postfix_bounce_queue_lifetime: 5d
```

### `postfix_minimal_backoff_time`

Type: `str`. Required: `false`.

Minimum delay between delivery retries.

Default:

```yaml
postfix_minimal_backoff_time: 300s
```

### `postfix_maximal_backoff_time`

Type: `str`. Required: `false`.

Maximum delay between delivery retries.

Default:

```yaml
postfix_maximal_backoff_time: 4000s
```

### `postfix_queue_run_delay`

Type: `str`. Required: `false`.

Interval between deferred-queue scans.

Default:

```yaml
postfix_queue_run_delay: 300s
```

### `postfix_log_file`

Type: `str`. Required: `false`.

Direct Postfix log path. Empty uses the system mail syslog facility and its
journal integration.

Default:

```yaml
postfix_log_file: ''
```

### `postfix_tls_loglevel`

Type: `int`. Required: `false`.

TLS connection summary logging level.

Default:

```yaml
postfix_tls_loglevel: 1
```

### `postfix_non_smtpd_milters`

Type: `list`. Required: `false`.

Milter endpoints for local sendmail submissions.

Default:

```yaml
postfix_non_smtpd_milters: []
```

### `postfix_milter_default_action`

Type: `str`. Required: `false`.

Action when an enabled Milter is unavailable.

Default:

```yaml
postfix_milter_default_action: tempfail
```

### `postfix_backup`

Type: `bool`. Required: `false`.

Enables backups of main.cf, master.cf, the log rotation configuration and
nonsecret built-in tables before replacement.

Default:

```yaml
postfix_backup: true
```

### `postfix_database`

Type: `dict`. Required: `false`.

Native connection options for the PostfixAdmin schema. Both mysql and pgsql
require hosts. A SELECT-only login over a Unix socket or verified TLS is
recommended.

Default:

```yaml
postfix_database: {}
```

### `postfix_database_queries`

Type: `dict`. Required: `false`.

Optional overrides of the PostfixAdmin queries for domains, mailboxes,
virtual_aliases, alias_domains, alias_domain_catchalls, senders,
alias_domain_senders and protected_senders.

Default:

```yaml
postfix_database_queries: {}
```

### `postfix_listeners`

Type: `dict`. Required: `false`.

Named TCP listeners with independent binding, TLS, authentication, relay and
recipient policies. Listener options also configure native postscreen policy on
a screened frontend.

Default:

```yaml
postfix_listeners: {}
```

### `postfix_outbound`

Type: `str`. Required: `false`.

Delivery path for nonlocal addresses. Closed mode rejects foreign recipients and
bounces local submissions to them.

Default:

```yaml
postfix_outbound: none
```

### `postfix_relayhost`

Type: `dict`. Required: `false`.

Next hop for relayhost mode. Authentication requires certificate-verified TLS.

Default:

```yaml
postfix_relayhost: {}
```

### `postfix_virtual_mailbox_domains`

Type: `list`. Required: `false`.

Virtual mailbox domains from inventory, supplemented by active PostfixAdmin
domains.

Default:

```yaml
postfix_virtual_mailbox_domains: []
```

### `postfix_virtual_alias_domains`

Type: `list`. Required: `false`.

Domains whose addresses must resolve through virtual alias maps.

Default:

```yaml
postfix_virtual_alias_domains: []
```

### `postfix_relay_domains`

Type: `list`. Required: `false`.

Domains forwarded to another mail server, restricted to the relay recipient
table.

Default:

```yaml
postfix_relay_domains: []
```

### `postfix_relay_recipients`

Type: `list`. Required: `false`.

Accepted recipient addresses in relay domains. An explicit @domain entry accepts
any address in that domain.

Default:

```yaml
postfix_relay_recipients: []
```

### `postfix_relay_transport`

Type: `str`. Required: `false`.

Postfix transport and optional next hop used for relay domains.

Default:

```yaml
postfix_relay_transport: relay
```

### `postfix_direct_tls`

Type: `str`. Required: `false`.

TLS policy for direct SMTP delivery. DANE requires a trusted DNSSEC-validating
resolver.

Default:

```yaml
postfix_direct_tls: may
```

### `postfix_tls_policy_maps`

Type: `list`. Required: `false`.

Additional native SMTP TLS policy tables searched after the managed destination
policies.

Default:

```yaml
postfix_tls_policy_maps: []
```

### `postfix_smtp_helo_name`

Type: `str`. Required: `false`.

Hostname announced by the outgoing SMTP client.

Default:

```yaml
postfix_smtp_helo_name: $myhostname
```

### `postfix_smtp_bind_address`

Type: `str`. Required: `false`.

Optional IPv4 source address for outgoing SMTP.

Default:

```yaml
postfix_smtp_bind_address: ''
```

### `postfix_smtp_bind_address6`

Type: `str`. Required: `false`.

Optional IPv6 source address for outgoing SMTP.

Default:

```yaml
postfix_smtp_bind_address6: ''
```

### `postfix_sasl_type`

Type: `str`. Required: `false`.

SMTP server authentication implementation.

Default:

```yaml
postfix_sasl_type: dovecot
```

### `postfix_cyrus_sasl_path`

Type: `str`. Required: `false`.

Cyrus SASL application name when the Cyrus server backend is selected.

Default:

```yaml
postfix_cyrus_sasl_path: smtpd
```

### `postfix_lmtp_tls_security_level`

Type: `str`. Required: `false`.

LMTP uses a local Unix socket by default. TCP defaults to secure and verifies
the peer against the trusted CA.

Default:

```yaml
postfix_lmtp_tls_security_level: secure
```

### `postfix_lmtp_tls_ca_file`

Type: `str`. Required: `false`.

CA bundle for TCP LMTP delivery. Empty selects the platform trust store.

Default:

```yaml
postfix_lmtp_tls_ca_file: ''
```

### `postfix_recipient_delimiter`

Type: `str`. Required: `false`.

Recipient address extension delimiters.

Default:

```yaml
postfix_recipient_delimiter: +
```

### `postfix_compatibility_level`

Type: `str`. Required: `false`.

Postfix compatibility level used by the installed daemon.

Default:

```yaml
postfix_compatibility_level: '3.6'
```

### `postfix_forbid_bare_newline`

Type: `str`. Required: `false`.

SMTP handling of bare newlines. Active listeners require a Postfix build
supporting the selected policy.

Default:

```yaml
postfix_forbid_bare_newline: normalize
```

### `postfix_bare_newline_exclusions`

Type: `list`. Required: `false`.

Client networks exempt from the SMTP bare-newline policy.

Default:

```yaml
postfix_bare_newline_exclusions:
  - $mynetworks
```

### `postfix_smtp_tls_protocols`

Type: `str`. Required: `false`.

Protocol bounds for both optional and mandatory TLS on outbound SMTP.

Default:

```yaml
postfix_smtp_tls_protocols: '>=TLSv1.2'
```

### `postfix_smtpd_tls_protocols`

Type: `str`. Required: `false`.

Protocol bounds for both optional and mandatory TLS on incoming SMTP.

Default:

```yaml
postfix_smtpd_tls_protocols: '>=TLSv1.2'
```

### `postfix_client_auth_rate_limit`

Type: `int`. Required: `false`.

Maximum authentication attempts per client per anvil rate interval (normally 60
seconds). Zero disables the limit.

Default:

```yaml
postfix_client_auth_rate_limit: 30
```

### `postfix_client_connection_rate_limit`

Type: `int`. Required: `false`.

Maximum new connections per client per anvil rate interval (normally 60
seconds). Zero disables the limit.

Default:

```yaml
postfix_client_connection_rate_limit: 60
```

### `postfix_client_connection_count_limit`

Type: `int`. Required: `false`.

Per-client limit on simultaneous connections. Zero disables this limit.

Default:

```yaml
postfix_client_connection_count_limit: 50
```

### `postfix_milter_protocol`

Type: `int`. Required: `false`.

Protocol version used by configured Milters.

Default:

```yaml
postfix_milter_protocol: 6
```

### `postfix_main_cf`

Type: `dict`. Required: `false`.

Additional single-line main.cf parameters. Role-owned delivery invariants apply
in closed mode.

Default:

```yaml
postfix_main_cf: {}
```

### `postfix_master_cf`

Type: `list`. Required: `false`.

Additional native master.cf services, each identified by a unique combination of
name and type.

Default:

```yaml
postfix_master_cf: []
```

### `postfix_tables`

Type: `dict`. Required: `false`.

Additional managed lookup tables keyed by name, with entries, type, optional
main.cf parameter and explicit secret flag.

Default:

```yaml
postfix_tables: {}
```

### `postfix_ldap_address_domains`

Type: `list`. Required: `false`.

Additional domains eligible for LDAP address lookups, including domains obtained
dynamically from SQL.

Default:

```yaml
postfix_ldap_address_domains: []
```

### `postfix_ldap_alias_queries`

Type: `dict`. Required: `false`.

Optional LDAP alias or distribution-list maps with a keyed address filter,
result attributes and optional recursive group attributes.

Default:

```yaml
postfix_ldap_alias_queries: {}
```

### `postfix_logrotate_interval`

Type: `str`. Required: `false`.

Rotation interval when direct file logging is enabled.

Default:

```yaml
postfix_logrotate_interval: daily
```

### `postfix_logrotate_count`

Type: `int`. Required: `false`.

Number of rotated Postfix log files to retain.

Default:

```yaml
postfix_logrotate_count: 14
```

## Managed Files

- `/etc/postfix/main.cf` Service-wide defaults, lookup chains and named
  per-listener restriction lists.
- `/etc/postfix/master.cf` SMTP listeners, delivery transports and optional
  postscreen or additional native services.
- `/etc/postfix/managed/` Address tables, native indexes and protected SQL, LDAP
  and relay connection settings.
- `/etc/logrotate.d/ansible-postfix` Installed when direct file logging is
  enabled and removed when switching to system logging.

## Check Mode

A check-mode run on a converged host reports zero changes.

## Service Behavior

The role gathers the facts it needs, including in plays with
`gather_facts: false`. It installs Postfix and the selected lookup
drivers and enables the service.

Before replacing `main.cf` or `master.cf`, the template validates the
proposed file together with its installed companion using `postfix check`.
When validation fails, the destination keeps its previous contents.
Correct the inventory and run the role again.

The role is idempotent. With identical inputs and intact indexes, a
second run reports zero changes. Changed, missing or stale indexes are
rebuilt with `postmap` or `postalias`.

Pending handlers run at the end of configuration, including after an
ordinary task failure. A hard interruption can lose a pending restart or
reload. In that case, apply the pending service action manually. If a
restart fails, correct the setting or restore the adjacent timestamped
backup made with `postfix_backup: true`, then start Postfix.

### Handlers

- A change to main.cf or master.cf restarts Postfix.
- A change to a text lookup table or a SQL or LDAP connection file reloads
  Postfix.

## Security Notes

- No TCP listeners are enabled by default. Each configured listener defaults to
  encrypted SMTP AUTH, authenticated relay and sender ownership checks. Root
  alone can submit via the local sendmail interface by default. Configure an
  explicit root alias to reach an operator.
- Direct file logging is optional. The default uses the system mail syslog
  facility, normally captured by journald. Native TLS logging records metadata.
- Provider credentials and secret custom tables are root-only. SQL and LDAP
  connection files are root:postfix 0640. Secret tasks suppress output, diffs
  and backups. Store passwords in Vault. Keep native Postfix and LDAP debugging
  disabled when bind credentials are in use.
- File sender ownership and SASL submission entitlement are independent. A
  successful Kerberos or PAM authentication still needs an explicit OK when
  postfix_sasl_access_enabled is true. LDAP outage or CA failure defers lookups.
  The SASL gate also covers the null envelope sender.
- With sender_login_match enabled, an unauthenticated receiving listener rejects
  envelope senders from local, virtual mailbox and virtual alias domains,
  including unassigned addresses. Active PostfixAdmin domains and their active
  aliases are protected, as are configured LDAP address domains when LDAP is
  enabled. Explicit file-based sender identities also remain protected. The null
  sender is allowed for delivery status notifications.
- An unauthenticated listener with relay set to clients accepts those senders
  from its configured client networks by default. Set sender_login_match to true
  on that listener to apply the same sender protection.
- Verify visible From headers with a submission Milter. Envelope checks compare
  SMTP MAIL FROM with the authenticated login.

## Operational Notes

- postfix_listeners is keyed by service name. Set port and optionally address,
  tls (none, may, encrypt, wrapper), auth (none, required), relay (none,
  authenticated, clients), clients, sender_login_match, milters and
  policy_services. Set mx for inbound checks and postscreen for pre-greeting
  screening. Set helo_restrictions, sender_restrictions, recipient_restrictions
  or native options on the individual listener.
- The SMTP server enforces command synchronization. The anvil defaults are 30
  AUTH attempts and 60 new connections per client and service in each
  anvil_rate_time_unit (normally 60 seconds). Account for shared client IPs when
  setting listener-specific limits. Zero disables the corresponding limit.
  Postfix normally exempts mynetworks through
  smtpd_client_event_limit_exceptions. client_connection_count_limit controls
  simultaneous connections.
- The MX preset checks sender domains, hides the ETRN and DSN extensions and
  rejects ETRN requests. Normal non-delivery reports still use the null envelope
  sender. For an authorized ETRN service, set both smtpd_discard_ehlo_keywords
  and smtpd_etrn_restrictions in its listener options.
- Each screened listener has its own writable cache. The platform settings
  select the cache driver for postscreen and address verification. Native
  postscreen_* listener options apply to the front end. For observation, set
  postscreen_greet_action and postscreen_dnsbl_action to ignore. Configure the
  actions for any additional tests you enable in the same options mapping.
- Closed outbound mode rejects foreign recipients even after SMTP AUTH and sends
  a permanent non-delivery notification for local submissions. Explicit
  transport routes and providers require an enabled outbound mode. Relay domains
  need listed recipients or explicit @domain catchalls.
- File entries take precedence over the PostfixAdmin backend and LDAP. The first
  matching sender map supplies the complete list of authorized identities.
  PostfixAdmin's active domains, mailboxes, aliases and alias domains are
  queried with the selected SQL driver. Disabled SQL records grant no rights.
- LDAP address maps are limited to postfix_virtual_mailbox_domains,
  postfix_virtual_alias_domains and postfix_ldap_address_domains. List
  SQL-managed domains used for LDAP in postfix_ldap_address_domains. The SASL
  login lookup accepts the login realm independently of the mailbox domain.
- Additional LDAP aliases and groups use postfix_ldap_alias_queries. Each filter
  includes the native escaped %s key, and operational filters select the
  intended recipients. For DN groups use special_result_attribute and
  leaf_result_attribute to return member addresses.
- postfix_tls_policies specifies per-next-hop TLS policies.
  postfix_tls_policy_maps can append a socketmap for an external MTA-STS
  service. DANE direct delivery requires a trusted DNSSEC-validating resolver. A
  private SMTP or LMTP CA supplements the system trust store.
- A unique provider next hop also gets a destination credential. Shared provider
  endpoints use sender-specific credentials, with the explicitly chosen default
  provider supplying the fallback. Set the sender's complete authorized identity
  list in postfix_sender_logins.
- postfix_tables accepts type (native, hash, btree, lmdb, cdb, cidr, regexp,
  pcre or texthash), entries, an optional parameter and an explicit secret flag.
  Native indexes use the platform table type. Pattern rules keep declaration
  order. Reference a custom table as $managed_table_NAME.
- postfix_main_cf accepts native single-line parameters. postfix_master_cf adds
  named service definitions with type, command and optional overrides. Treat
  these interfaces as privileged configuration. Use listener fields for
  authentication and relay decisions.
- For Cyrus set postfix_sasl_type to cyrus and configure postfix_cyrus_sasl_path
  for the backend application. The role consumes the provider's authentication
  service. TCP LMTP verifies the certificate by default. Use a DNS hostname for
  the peer and supply its CA for a private PKI.
- postqueue -p lists deferred deliveries. postqueue -f requests an immediate
  retry. The role preserves queued messages across reloads.

## Supported Platforms

| OS Family | Distribution | Version | Container Image |
| --------- | ------------ | ------- | --------------- |
| RedHat | AlmaLinux | latest | [jomrr/molecule-almalinux:latest](https://hub.docker.com/r/jomrr/molecule-almalinux) |
| Debian | Debian | latest | [jomrr/molecule-debian:latest](https://hub.docker.com/r/jomrr/molecule-debian) |
| RedHat | Fedora | latest | [jomrr/molecule-fedora:latest](https://hub.docker.com/r/jomrr/molecule-fedora) |
| Suse | OpenSuse Leap | latest | [jomrr/molecule-opensuse-leap:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-leap) |
| Suse | OpenSuse Tumbleweed | latest | [jomrr/molecule-opensuse-tumbleweed:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-tumbleweed) |
| Debian | Ubuntu | latest | [jomrr/molecule-ubuntu:latest](https://hub.docker.com/r/jomrr/molecule-ubuntu) |

## Example Playbook

### Closed local MTA

With no variables, only root can submit through sendmail. Mail to a
foreign domain bounces locally. Set the root alias to a monitored local
mailbox, or enable an outbound route for an external destination.

```yaml
postfix_local_aliases:
  postmaster: root
  mailer-daemon: postmaster
  abuse: postmaster
  root: operator
```

### Internal mail hub

Accept local and virtual recipients on an authenticated submission
listener. Both SMTP clients and local submitters are subject to the
closed outbound policy. Dovecot provides the authentication socket.

```yaml
postfix_outbound: none
postfix_tls_certificate: /etc/ssl/mail/fullchain.pem
postfix_tls_private_key: /etc/ssl/mail/key.pem
postfix_listeners:
  submission: {address: 192.0.2.10, port: 587}
```

### Null client with verified TLS to a relay

Send all local submissions to a single next hop. The relay certificate
must match its hostname. For SMTP AUTH, add username and a Vault-supplied
password to postfix_relayhost. Use tls=wrapper for implicit TLS.

```yaml
postfix_local_domains: []
postfix_outbound: relayhost
postfix_relayhost: {host: mail.example.org, port: 25, tls: secure}
postfix_tls_ca_file: /etc/mail/private-ca.pem
```

### Relay for application networks

The source ACL and the relay authorization use the same explicit CIDRs.
Bind only on a network under the operator's control.

```yaml
postfix_outbound: direct
postfix_listeners:
  applications:
    address: 192.0.2.10
    port: 2525
    tls: none
    auth: none
    relay: clients
    clients: [192.0.2.0/28]
    sender_login_match: false
```

### Public MX and gateway for a downstream domain

The MX preset enables HELO, sender and recipient checks. The optional
postscreen service screens connections before handing them to smtpd.
Specify DNSBL zones authorized for your site under dnsbl_sites. The relay
recipient table limits accepted gateway addresses at RCPT TO.

```yaml
postfix_interfaces: [all]
postfix_outbound: direct
postfix_tls_certificate: /etc/ssl/mail/fullchain.pem
postfix_tls_private_key: /etc/ssl/mail/key.pem
postfix_relay_domains: [branch.example.org]
postfix_relay_recipients: [office@branch.example.org]
postfix_relay_transport: 'relay:[inside.example.org]:25'
postfix_listeners:
  mx: {port: 25, auth: none, tls: may, relay: none, mx: true, postscreen: true}
```

### DKIM, SPF, DMARC and recipient quota policies

Connect submission to a DKIM signing Milter and Dovecot's quota-status
service. On the public MX, run DKIM verification before the DMARC
Milter and check SPF through a policy service. The endpoints shown here
belong to separately provisioned services.

```yaml
postfix_outbound: direct
postfix_interfaces: [all]
postfix_tls_certificate: /etc/ssl/mail/fullchain.pem
postfix_tls_private_key: /etc/ssl/mail/key.pem
postfix_listeners:
  submission:
    port: 587
    milters: ['inet:127.0.0.1:8891']
    policy_services: ['inet:127.0.0.1:12340']
    client_auth_rate_limit: 15
  mx:
    port: 25
    auth: none
    tls: may
    relay: none
    mx: true
    milters: ['inet:127.0.0.1:8891', 'inet:127.0.0.1:8893']
    policy_services: ['unix:private/policy-spf']
    client_connection_rate_limit: 120
```

### Both Sieve return paths and Fetchmail

For Dovecot's sendmail path, authorize the mailbox Unix user and its
required envelope senders. Vacation replies typically use the null
sender. For per-user mailboxes use each applicable Unix identity.
For SMTP submission point Dovecot's submission_host at the internal
applications port. Any process able to connect from a trusted address
shares that relay permission. Fetchmail uses a separate local-only
destination policy and can preserve the original envelope sender.

```yaml
postfix_outbound: direct
postfix_local_submitters:
  root: ['*']
  vmail: ['<>', owner@example.org]
postfix_listeners:
  sieve:
    address: 127.0.0.1
    port: 2526
    auth: none
    tls: none
    relay: clients
    clients: [127.0.0.1/32]
    sender_login_match: false
  fetchmail:
    address: 127.0.0.1
    port: 2525
    auth: none
    tls: none
    relay: none
    clients: [127.0.0.1/32]
    sender_login_match: false
```

### File accounts with Dovecot and two provider identities

Dovecot, TLS material and archive mailboxes are provisioned separately. Each
named provider may use the same hostname with different credentials. Vault
variables contain the real secrets.

```yaml
---
- name: Configure submission and fetched mail
  hosts: mailservers
  gather_facts: true
  roles:
    - role: jomrr.postfix
      postfix_hostname: mail.example.org
      postfix_interfaces: [all]
      postfix_outbound: direct
      postfix_listeners:
        submission: {port: 587}
        fetchmail:
          address: 127.0.0.1
          port: 2525
          clients: [127.0.0.1/32]
          relay: none
          sender_login_match: false
      postfix_tls_certificate: /etc/ssl/mail/fullchain.pem
      postfix_tls_private_key: /etc/ssl/mail/key.pem
      postfix_virtual_mailbox_domains: [example.org]
      postfix_mailboxes: [alice@example.org, archive@example.org]
      postfix_virtual_aliases:
        sales@example.org: [alice@example.org]
      postfix_sender_logins:
        alice@example.org: [alice@example.org]
        sales@example.org: [alice@example.org]
      postfix_providers:
        - name: personal
          host: smtp.provider.example
          username: personal-account
          password: "{{ vault_personal_password }}"
        - name: business
          host: smtp.provider.example
          port: 465
          tls: wrapper
          username: business-account
          password: "{{ vault_business_password }}"
      postfix_sender_relays:
        alice@example.org: personal
        sales@example.org: business
      postfix_default_provider: personal
      postfix_sender_bcc:
        alice@example.org: archive@example.org
      postfix_recipient_bcc:
        alice@example.org: archive@example.org
```

### Authorize Active Directory submission and a local relay account

Configure the authenticated listeners and Dovecot socket as in the
submission example. Dovecot authenticates the password or Kerberos ticket.
Postfix checks entitlement at RCPT TO, including for the null envelope
sender. The listener enforces sender ownership by default.

This filter selects direct MailUsers members and excludes disabled AD
accounts. A user with UPN `alice@ad.example.org` and mail `alice@example.org`
submits as `alice@ad.example.org` and may send from `alice@example.org`.
A separate Dovecot relay login has explicit permission to send from
`root@app.example.org`. Keep its login unique across authentication sources.

```yaml
postfix_virtual_mailbox_domains: [example.org]
mail_filter: "(&(objectClass=user)(memberOf=CN=MailUsers,OU=Groups,DC=ad,DC=example,DC=org)\
  (!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
dovecot_ldap:
  # Merge this with the Dovecot connection settings in the same inventory.
  user_filter: "(&{{ mail_filter }}(|(mail=%{user})(userPrincipalName=%{user})))"
postfix_ldap_enabled: true
postfix_ldap:
  uris: [ldaps://dc1.ad.example.org, ldaps://dc2.ad.example.org]
  base: DC=ad,DC=example,DC=org
  bind_dn: CN=mail-reader,OU=Services,DC=ad,DC=example,DC=org
  bind_password: "{{ vault_mail_ldap_password }}"
  ca_file: /etc/mail/directory-ca.pem
  eligibility_filter: "{{ mail_filter }}"
  mail_attribute: mail
  login_attribute: userPrincipalName
postfix_sasl_access_enabled: true
postfix_sasl_access_logins: [relay@example.org]
postfix_sender_logins:
  root@app.example.org: [relay@example.org]
```

### LDAP alternate addresses and distribution groups

Extend the AD example with an address lookup and a DN-based group
lookup. Group ownership and membership are administered in the directory.

```yaml
postfix_ldap_alias_queries:
  aliases:
    filter: "(&{{ mail_filter }}(proxyAddresses=smtp:%s))"
    result_attribute: mail
  lists:
    filter: "(&(objectClass=group)(mail=%s))"
    special_result_attribute: member
    leaf_result_attribute: mail
```

### Header checks and native settings

Apply ordered header rules, a canonical sender rewrite and an external
content filter. The filter delivers onward or reinjects on a dedicated
listener that clears content_filter.

```yaml
postfix_outbound: direct
postfix_tables:
  headers:
    type: regexp
    parameter: header_checks
    entries: {'/^X-Internal-Token:/': IGNORE}
  origins:
    parameter: sender_canonical_maps
    entries: {root@node.example.org: ops@example.org}
postfix_main_cf:
  smtp_helo_name: outbound.example.org
  content_filter: 'smtp:[127.0.0.1]:10024'
```

### PostfixAdmin with a local MariaDB socket

PostfixAdmin maintains domains, recipients and aliases. Its schema and the
SELECT-only postfix database login already exist. The connection options
below are added to the same playbook as the submission and TLS settings
above.

```yaml
postfix_account_backend: mysql
postfix_database:
  hosts: unix:/run/mysqld/mysqld.sock
  dbname: postfixadmin
  user: postfix
  password: "{{ vault_postfix_database_password }}"
```

### PostfixAdmin with verified PostgreSQL TLS

Store the complete connection URI, including credentials and
sslmode=verify-full, in Ansible Vault. Reference the CA using sslrootcert in
the URI. The role applies the same PostfixAdmin queries to both backends.

```yaml
postfix_account_backend: pgsql
postfix_database:
  hosts: "{{ vault_postfix_postgresql_uri }}"
```

## References

- [Postfix LDAP tables](https://www.postfix.org/ldap_table.5.html)
- [Postfix SASL access checks](https://www.postfix.org/postconf.5.html#check_sasl_access)
- [Dovecot role and external authentication](https://github.com/jomrr/ansible-role-dovecot#security-notes)
- [Postfix SASL](https://www.postfix.org/SASL_README.html)
- [Postfix TLS](https://www.postfix.org/TLS_README.html)
- [Postfix TLS policy maps](https://www.postfix.org/postconf.5.html#smtp_tls_policy_maps)
- [Postfix null client](https://www.postfix.org/STANDARD_CONFIGURATION_README.html#null_client)
- [Postfix lookup proxy](https://www.postfix.org/proxymap.8.html)
- [PostfixAdmin SQL integration](https://github.com/postfixadmin/postfixadmin/blob/master/DOCUMENTS/POSTFIX_CONF.txt)
- [Dovecot SASL](https://doc.dovecot.org/main/howto/sasl/postfix.html)
- [Dovecot LMTP](https://doc.dovecot.org/latest/howto/lmtp/postfix.html)

## Author

[Jonas Mauer](https://github.com/jomrr)

## License

This project is licensed under the MIT License.
See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2026 Jonas Mauer.
