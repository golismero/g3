-- SQL tables for Golismero3. Requires MariaDB 10.7+.

CREATE DATABASE IF NOT EXISTS golismero;
USE golismero;

CREATE TABLE IF NOT EXISTS scans (
    scanid UUID PRIMARY KEY NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'waiting',
    progress INTEGER UNSIGNED NOT NULL DEFAULT 0,
    message VARCHAR(255) DEFAULT NULL,
    created_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
    started_at BIGINT UNSIGNED DEFAULT NULL,
    ended_at BIGINT UNSIGNED DEFAULT NULL,
    last_updated_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
    last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0,
    INDEX(created_at, scanid),
    CONSTRAINT chk_scans_progress CHECK (progress <= 100),
    CONSTRAINT chk_scans_ts CHECK (
        (created_at > 0) AND
        (last_updated_at >= created_at) AND
        (started_at IS NULL OR (started_at >= created_at AND started_at <= last_updated_at)) AND
        (ended_at IS NULL OR (
            ended_at <= last_updated_at AND
            ended_at >= created_at AND
            (started_at IS NULL OR ended_at >= started_at)
        ))
    ),
    CONSTRAINT chk_scans_status CHECK (
        status IN ('managed','waiting','dispatched','running','canceled','done','warning','error')
    )
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS tasks (
    taskid UUID PRIMARY KEY NOT NULL,
    scanid UUID NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'waiting',
    tool VARCHAR(64) DEFAULT NULL,
    worker VARCHAR(64) DEFAULT NULL,
    created_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
    started_at BIGINT UNSIGNED DEFAULT NULL,
    ended_at BIGINT UNSIGNED DEFAULT NULL,
    last_updated_at BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
    last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0,
    FOREIGN KEY (scanid) REFERENCES scans(scanid) ON DELETE CASCADE,
    CONSTRAINT chk_tasks_ts CHECK (
        (created_at > 0) AND
        (last_updated_at >= created_at) AND
        (started_at IS NULL OR (started_at >= created_at AND started_at <= last_updated_at)) AND
        (ended_at IS NULL OR (
            ended_at <= last_updated_at AND
            ended_at >= created_at AND
            (started_at IS NULL OR ended_at >= started_at)
        ))
    ),
    CONSTRAINT chk_tasks_status CHECK (
        status IN ('waiting','dispatched','running','canceled','done','warning','error')
    )
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS logs (
    id BIGINT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
    timestamp BIGINT UNSIGNED NOT NULL DEFAULT UNIX_TIMESTAMP(),
    scanid UUID NOT NULL,
    taskid UUID NOT NULL,
    text TEXT NOT NULL,
    FOREIGN KEY (scanid) REFERENCES scans(scanid) ON DELETE CASCADE,
    FOREIGN KEY (taskid) REFERENCES tasks(taskid) ON DELETE CASCADE,
    INDEX (taskid, timestamp, id),
    INDEX (scanid, timestamp, id),
    CONSTRAINT chk_logs_ts CHECK (timestamp > 0)
) ENGINE = InnoDB;

DELIMITER $$
CREATE TRIGGER IF NOT EXISTS trg_scans_transition
BEFORE UPDATE ON scans
FOR EACH ROW
BEGIN
    IF OLD.status = 'managed' THEN

        -- No status transitions allowed for managed scans. Almost everything else is editable.
        IF NEW.status <> OLD.status THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'illegal status transition';
        END IF;

    ELSE

        IF NEW.status <> OLD.status THEN

            -- Legal status transitions.
            IF NOT (
                (OLD.status = 'waiting'    AND NEW.status IN ('dispatched','running','canceled','error')) OR
                (OLD.status = 'dispatched' AND NEW.status IN ('running','canceled','error'))    OR
                (OLD.status = 'running'    AND NEW.status IN ('canceled','error','warning','done'))
            ) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'illegal status transition';
            END IF;

            -- Update the timestamps on status transitions.
            IF NEW.status = 'running' THEN
                SET NEW.started_at = UNIX_TIMESTAMP();
            END IF;
            IF NEW.status IN ('canceled','done','warning','error') THEN
                SET NEW.ended_at = UNIX_TIMESTAMP();
            END IF;

        ELSE

            -- No status transition, guard against tampering.
            IF NOT (NEW.created_at <=> OLD.created_at) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'created_at may not change after creation';
            END IF;
            IF NOT (NEW.started_at <=> OLD.started_at) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'started_at may not change without a status transition';
            END IF;
            IF NOT (NEW.ended_at <=> OLD.ended_at) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'ended_at may not change without a status transition';
            END IF;

        END IF;

    END IF;

    -- Always check the last sequence number (for scans it is provided in the message).
    IF NEW.last_seq <= OLD.last_seq THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'invalid sequence number';
    END IF;

    -- Always bump last_updated_at.
    SET NEW.last_updated_at = UNIX_TIMESTAMP();
END$$

CREATE TRIGGER IF NOT EXISTS trg_tasks_transition
BEFORE UPDATE ON tasks
FOR EACH ROW
BEGIN
    IF NEW.status <> OLD.status THEN

        -- Legal status transitions.
        IF NOT (
            (OLD.status = 'waiting'    AND NEW.status IN ('dispatched','running','canceled','error')) OR
            (OLD.status = 'dispatched' AND NEW.status IN ('running','canceled','error'))    OR
            (OLD.status = 'running'    AND NEW.status IN ('canceled','error','warning','done'))
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'illegal status transition';
        END IF;

        -- Update the timestamps on status transitions.
        IF NEW.status = 'running' THEN
            SET NEW.started_at = UNIX_TIMESTAMP();
        END IF;
        IF NEW.status IN ('canceled','done','warning','error') THEN
            SET NEW.ended_at = UNIX_TIMESTAMP();
        END IF;

    ELSE

        -- No status transition, guard against tampering.
        IF NOT (NEW.created_at <=> OLD.created_at) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'created_at may not change after creation';
        END IF;
        IF NOT (NEW.started_at <=> OLD.started_at) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'started_at may not change without a status transition';
        END IF;
        IF NOT (NEW.ended_at <=> OLD.ended_at) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'ended_at may not change without a status transition';
        END IF;

    END IF;

    -- Always bump last_updated_at and last_seq.
    SET NEW.last_updated_at = UNIX_TIMESTAMP();
    SET NEW.last_seq = OLD.last_seq + 1;
END$$
DELIMITER ;
