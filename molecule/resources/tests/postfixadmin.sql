-- Only the PostfixAdmin columns read by Postfix are needed by this fixture.
CREATE TABLE domain (domain VARCHAR(255) PRIMARY KEY, active BOOLEAN, backupmx BOOLEAN);
CREATE TABLE mailbox (username VARCHAR(255) PRIMARY KEY, domain VARCHAR(255), active BOOLEAN);
CREATE TABLE alias (address VARCHAR(255) PRIMARY KEY, goto TEXT, domain VARCHAR(255), active BOOLEAN);
CREATE TABLE alias_domain (alias_domain VARCHAR(255) PRIMARY KEY, target_domain VARCHAR(255), active BOOLEAN);
INSERT INTO domain VALUES ('example.test', TRUE, FALSE), ('disabled.test', FALSE, FALSE), ('backup.test', TRUE, TRUE);
INSERT INTO mailbox VALUES
    ('alice@example.test', 'example.test', TRUE),
    ('bob@example.test', 'example.test', TRUE),
    ('archive@example.test', 'example.test', TRUE),
    ('disabled@example.test', 'example.test', FALSE);
INSERT INTO alias VALUES
    ('alice@example.test', 'alice@example.test', 'example.test', TRUE),
    ('bob@example.test', 'bob@example.test', 'example.test', TRUE),
    ('archive@example.test', 'archive@example.test', 'example.test', TRUE),
    ('sales@example.test', 'alice@example.test,bob@example.test', 'example.test', TRUE);
INSERT INTO alias_domain VALUES ('alias.test', 'example.test', TRUE), ('disabled-alias.test', 'example.test', FALSE);
