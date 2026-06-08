-- SQL tables for Golismero3.

-- Tool execution logs.
CREATE TABLE `golismero`.`logs` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `timestamp` INTEGER UNSIGNED NOT NULL,
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
    `progress` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `message` TEXT NOT NULL DEFAULT "",
    `last_seq` BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE = InnoDB;
