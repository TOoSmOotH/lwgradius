-- FreeRADIUS SQLite schema
-- This file defines the database schema for the FreeRADIUS server with TOTP support

-- Create tables for user authentication
CREATE TABLE IF NOT EXISTS radcheck (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    attribute TEXT NOT NULL,
    op CHAR(2) NOT NULL DEFAULT '==',
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS radcheck_username ON radcheck(username);

CREATE TABLE IF NOT EXISTS radreply (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    attribute TEXT NOT NULL,
    op CHAR(2) NOT NULL DEFAULT '=',
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS radreply_username ON radreply(username);

CREATE TABLE IF NOT EXISTS radusergroup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    groupname TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS radusergroup_username ON radusergroup(username);

CREATE TABLE IF NOT EXISTS radgroupcheck (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    groupname TEXT NOT NULL,
    attribute TEXT NOT NULL,
    op CHAR(2) NOT NULL DEFAULT '==',
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS radgroupcheck_groupname ON radgroupcheck(groupname);

CREATE TABLE IF NOT EXISTS radgroupreply (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    groupname TEXT NOT NULL,
    attribute TEXT NOT NULL,
    op CHAR(2) NOT NULL DEFAULT '=',
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS radgroupreply_groupname ON radgroupreply(groupname);

-- Create accounting table
CREATE TABLE IF NOT EXISTS radacct (
    radacctid INTEGER PRIMARY KEY AUTOINCREMENT,
    acctsessionid TEXT NOT NULL,
    acctuniqueid TEXT NOT NULL,
    username TEXT NOT NULL,
    realm TEXT,
    nasipaddress TEXT NOT NULL,
    nasportid TEXT,
    nasporttype TEXT,
    acctstarttime TIMESTAMP,
    acctupdatetime TIMESTAMP,
    acctstoptime TIMESTAMP,
    acctinterval INTEGER,
    acctsessiontime INTEGER,
    acctauthentic TEXT,
    connectinfo_start TEXT,
    connectinfo_stop TEXT,
    acctinputoctets BIGINT,
    acctoutputoctets BIGINT,
    calledstationid TEXT,
    callingstationid TEXT,
    acctterminatecause TEXT,
    servicetype TEXT,
    framedprotocol TEXT,
    framedipaddress TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS radacct_username ON radacct(username);
CREATE INDEX IF NOT EXISTS radacct_acctsessionid ON radacct(acctsessionid);
CREATE INDEX IF NOT EXISTS radacct_acctstarttime ON radacct(acctstarttime);
CREATE INDEX IF NOT EXISTS radacct_acctstoptime ON radacct(acctstoptime);
CREATE INDEX IF NOT EXISTS radacct_nasipaddress ON radacct(nasipaddress);
CREATE UNIQUE INDEX IF NOT EXISTS radacct_acctuniqueid ON radacct(acctuniqueid);

-- Create NAS table
CREATE TABLE IF NOT EXISTS nas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nasname TEXT NOT NULL,
    shortname TEXT,
    type TEXT NOT NULL DEFAULT 'other',
    ports INTEGER,
    secret TEXT NOT NULL,
    server TEXT,
    community TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS nas_nasname ON nas(nasname);

-- Create TOTP users table
CREATE TABLE IF NOT EXISTS totp_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    secret TEXT NOT NULL,
    last_used INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS totp_users_username ON totp_users(username);

-- Create admin users table for Web UI
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'admin',
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS admin_users_username ON admin_users(username);

-- Insert default admin user (username: admin, password: changeme)
INSERT OR IGNORE INTO admin_users (username, password_hash, role)
VALUES ('admin', 'changeme', 'admin');

-- Insert test user with TOTP
INSERT OR IGNORE INTO radcheck (username, attribute, op, value)
VALUES ('testuser', 'Cleartext-Password', ':=', 'password');

-- Example of how to add a TOTP secret for a user
-- INSERT OR IGNORE INTO radcheck (username, attribute, op, value)
-- VALUES ('testuser', 'TOTP-Secret', ':=', 'JBSWY3DPEHPK3PXP');