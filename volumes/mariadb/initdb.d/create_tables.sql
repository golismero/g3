-- SQL tables for Golismero3.

-- Tool execution logs.
CREATE TABLE `golismero`.`logs` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `timestamp` INTEGER NOT NULL,
    `scanid` UUID NOT NULL,
    `taskid` UUID NOT NULL,
    `text` TEXT NOT NULL,
    INDEX (`scanid`, `taskid`)
) ENGINE = InnoDB;

-- Scan progress updates.
CREATE TABLE `golismero`.`progress` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `scanid` UUID UNIQUE NOT NULL,
    `status` TEXT NOT NULL DEFAULT "WAITING",
    `progress` INTEGER NOT NULL DEFAULT 0,
    `message` TEXT NOT NULL DEFAULT ""
) ENGINE = InnoDB;
