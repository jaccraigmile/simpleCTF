CREATE DATABASE IF NOT EXISTS `bankingai`;
USE `bankingai`;

--
-- Table: login_attempts
--
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id`           INT(11)      NOT NULL AUTO_INCREMENT,
  `username`     VARCHAR(50)  DEFAULT NULL,
  `attempt_time` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `success`      TINYINT(1)   DEFAULT NULL,
  `ip_address`   VARCHAR(45)  DEFAULT NULL,
  `user_agent`   VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

INSERT INTO `login_attempts` VALUES
  (1, '\' OR 1=1 -- ',   '2025-10-13 12:09:00', 0, '172.16.0.1',   'Mozilla/5.0'),
  (2, 'admin',            '2025-10-13 12:10:00', 0, '172.16.0.1',   'Mozilla/5.0'),
  (3, 'ajohnson',         '2025-10-14 08:01:00', 1, '10.0.0.45',    'Mozilla/5.0'),
  (4, 'ajohnson',         '2025-10-15 08:03:00', 1, '10.0.0.45',    'Mozilla/5.0'),
  (5, 'ewright',          '2025-10-15 09:15:00', 1, '10.0.0.12',    'Mozilla/5.0'),
  (6, 'jdoe',             '2025-10-15 09:22:00', 1, '10.0.0.8',     'Mozilla/5.0'),
  (7, 'ajohnson',         '2025-11-01 08:00:00', 1, '10.0.0.45',    'Mozilla/5.0'),
  (8, '',                 '2025-11-15 21:24:47', 0, '100.64.0.21',  'sqlmap/1.9.4#stable (https://sqlmap.org)'),
  (9, '',                 '2025-11-17 03:22:18', 0, '100.64.0.106', 'sqlmap/1.9.8#stable (https://sqlmap.org)');

--
-- Table: staff_directory
--
CREATE TABLE IF NOT EXISTS `staff_directory` (
  `id`         INT(11)      NOT NULL AUTO_INCREMENT,
  `full_name`  VARCHAR(100) DEFAULT NULL,
  `email`      VARCHAR(100) DEFAULT NULL,
  `department` VARCHAR(50)  DEFAULT NULL,
  `role_title` VARCHAR(50)  DEFAULT NULL,
  `phone`      VARCHAR(20)  DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

INSERT INTO `staff_directory` VALUES
  (1,  'Alice Johnson',  'alice.johnson@bankingai.cloud',  'Finance',    'Accountant',          '555-1010'),
  (2,  'Brian Lee',      'brian.lee@bankingai.cloud',      'IT',         'Systems Engineer',    '555-2020'),
  (3,  'Carla Smith',    'carla.smith@bankingai.cloud',    'HR',         'HR Manager',          '555-3030'),
  (4,  'David Patel',    'david.patel@bankingai.cloud',    'Security',   'Analyst',             '555-4040'),
  (5,  'Evelyn Wright',  'evelyn.wright@bankingai.cloud',  'Executive',  'CFO',                 '555-5050'),
  (6,  'Frank Miller',   'frank.miller@bankingai.cloud',   'IT',         'Helpdesk Technician', '555-6060'),
  (7,  'Grace Kim',      'grace.kim@bankingai.cloud',      'Legal',      'Compliance Officer',  '555-7070'),
  (8,  'Henry Adams',    'henry.adams@bankingai.cloud',    'Finance',    'Auditor',             '555-8080'),
  (9,  'Isabella Lopez', 'isabella.lopez@bankingai.cloud', 'Marketing',  'Communications Lead', '555-9090'),
  (10, 'John Doe',       'john.doe@bankingai.cloud',       'Executive',  'Administrator',       '555-1111'),
  (11, 'Karen Brooks',   'karen.brooks@bankingai.cloud',   'Finance',    'Controller',          '555-1212'),
  (12, 'Liam Chen',      'liam.chen@bankingai.cloud',      'IT',         'Network Engineer',    '555-1313'),
  (13, 'Maria Gonzalez', 'maria.gonzalez@bankingai.cloud', 'HR',         'Recruiter',           '555-1414'),
  (14, 'Nathan Scott',   'nathan.scott@bankingai.cloud',   'Security',   'Incident Responder',  '555-1515'),
  (15, 'Olivia Brown',   'olivia.brown@bankingai.cloud',   'Legal',      'Paralegal',           '555-1616'),
  (16, 'Paul Edwards',   'paul.edwards@bankingai.cloud',   'Finance',    'Treasury Analyst',    '555-1717'),
  (17, 'Quincy Davis',   'quincy.davis@bankingai.cloud',   'IT',         'DevOps Engineer',     '555-1818'),
  (18, 'Rachel Green',   'rachel.green@bankingai.cloud',   'Marketing',  'Brand Manager',       '555-1919'),
  (19, 'Samuel Turner',  'samuel.turner@bankingai.cloud',  'Operations', 'Operations Manager',  '555-2021'),
  (20, 'Tina Hughes',    'tina.hughes@bankingai.cloud',    'Executive',  'CEO Assistant',       '555-2121');

--
-- Table: users
--
CREATE TABLE IF NOT EXISTS `users` (
  `id`       INT(11)              NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50)          DEFAULT NULL,
  `password` CHAR(32)             DEFAULT NULL,
  `role`     ENUM('user','admin')  DEFAULT 'user',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- Passwords are MD5 hashed. ajohnson = Staff@2024
INSERT INTO `users` VALUES
  (1,  'ajohnson',  '0516a6890fc52b7a7b040e6fbe06b661', 'user'),
  (2,  'blee',      '3fc0a7acf087f549ac2b266baf94b8b1', 'user'),
  (3,  'csmith',    '0d107d09f5bbe40cade3de5c71e9e9b7', 'user'),
  (4,  'dpatel',    'b11d49f3630e78c3ab484e3c311963e7', 'user'),
  (5,  'ewright',   'b56e0b4ea4962283bee762525c2d490f', 'admin'),
  (6,  'fmiller',   '201f00b5ca5d65a1c118e5e32431514c', 'user'),
  (7,  'gkim',      'e9aecb868cc4e8b00a5cd8cbe00f7680', 'user'),
  (8,  'hadams',    'd33542b8458db8cabd9843fe7c1e8784', 'user'),
  (9,  'ilopez',    'c769c2bd15500dd906102d9be97fdceb', 'user'),
  (10, 'jdoe',      '0192023a7bbd73250516f069df18b500', 'admin'),
  (11, 'kbrooks',   '594c103f2c6e04c3d8ab059f031e0c1a', 'user'),
  (12, 'lchen',     '200176387d36476522d4b488e8597847', 'user'),
  (13, 'mgonzalez', 'c8cd2c849347cdac6618ff2e7eab6502', 'user'),
  (14, 'nscott',    '3e072748feb6ecd1b1ba397704e009c0', 'user'),
  (15, 'obrown',    '1dd5170e462a852be0e409bd91f7ea0e', 'user'),
  (16, 'pedwards',  '51b77f45e04a44c06147ddf8c0ecbfec', 'user'),
  (17, 'qdavis',    'b0ecb4bf15e8435176cdf7ea8a82dfd6', 'user'),
  (18, 'rgreen',    'ec8c4469eec52240122d1e79b3bf5daf', 'user'),
  (19, 'sturner',   '742fc660f987728316da93a61e1c409a', 'user'),
  (20, 'thughes',   'f549cd73f694aa6f5541b4ae30894eea', 'user'),
  (22, 'FLAG_CREDENTIAL_HARVESTER_PLACEHOLDER', 'eb023a096ec66b1a04f75baa2c104b4e', 'user');
