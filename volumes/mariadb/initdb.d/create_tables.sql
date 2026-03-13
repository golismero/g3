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

-- Users and bcrypt'ed passwords.
CREATE TABLE `golismero`.`users` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `username` TEXT UNIQUE NOT NULL,
    `password` TEXT(60) NOT NULL
) ENGINE = InnoDB;

-- Access permissions to scans.
CREATE TABLE `golismero`.`scans` (
    `id` INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `userid` INTEGER NOT NULL,
    `scanid` UUID NOT NULL,
    FOREIGN KEY (`userid`) REFERENCES `users`(`id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;

-- Default admin credentials are: admin:admin
-- Default user credentials are: user:user
INSERT INTO `golismero`.`users` (`username`, `password`) VALUES ("admin", "$2a$10$P8FZRdQpPtPBUdkCubDz/eR/0Bu7m4WF3qwHnGN.PISJMm7nsmM9e");
INSERT INTO `golismero`.`users` (`username`, `password`) VALUES ("user", "$2a$12$ogNoAnoS1sPC1jeEBAFdyuv65E6FgbSAZuaMZRbtYqWtLdNfZQQVi");
