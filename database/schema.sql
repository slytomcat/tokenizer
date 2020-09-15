CREATE DATABASE `tokenizer`;

CREATE USER 'tokenizer'@'%' IDENTIFIED BY RANDOM PASSWORD;

GRANT SELECT, INSERT, UPDATE ON `tokenizer`.* TO `tokenizer`@`%`;

USE `tokenizer`;

DROP TABLE IF EXISTS `token`, `asset`, `osystem`, `trsecrets`;

CREATE TABLE `token` (
  `tur` varchar(60) NOT NULL,
  `osys` varchar(30) DEFAULT NULL,
  `trid` varchar(20) DEFAULT NULL,
  `status` varchar(16) DEFAULT NULL,
  `statustimestamp` timestamp NULL DEFAULT NULL,
  `last4` varchar(4) DEFAULT NULL,
  `assuranceLevel` decimal DEFAULT NULL,  
  `cobranded` boolean DEFAULT NULL, 
  `cobrandName` varchar(60) DEFAULT NULL, 
  `issuerName` varchar(60) DEFAULT NULL,
  `assetURL` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`tur`)
) ENGINE=InnoDB;

CREATE TABLE `asset` (
  `id` varchar(60) NOT NULL,
  `url` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

CREATE TABLE `osystem` (
  `osys` varchar(30) NOT NULL,
  `cburl` varchar(100) DEFAULT NULL,
  `tridurl` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`osys`)
) ENGINE=InnoDB;

CREATE TABLE `trsecrets` (
  `trid` varchar(20) NOT NULL,
  `apikey` varchar(100) DEFAULT NULL,
  `decyptkey` blob,
  `encryptkey` blob,
  `signkey` blob,
  PRIMARY KEY (`trid`)
) ENGINE=InnoDB;

CREATE TABLE `merchants` (
  `id` varchar(60) NOT NULL,
  `osys` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;


