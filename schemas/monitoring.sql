-- MySQL dump 10.13  Distrib 5.5.41, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: monitoring
-- ------------------------------------------------------
-- Server version	5.5.41-0ubuntu0.14.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `monitoring`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `monitoring` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `monitoring`;

--
-- Table structure for table `bandwidth`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `bandwidth` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int(10) unsigned NOT NULL,
  `network` varchar(16) NOT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gps_id` int(10) unsigned DEFAULT NULL,
  `bw_down` double DEFAULT NULL,
  `bw_up` double DEFAULT NULL,
  `type` enum('TCP','UDP') DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`,`network`,`time`),
  KEY `gps_id` (`gps_id`),
  CONSTRAINT `bandwidth_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `bandwidth_ibfk_2` FOREIGN KEY (`gps_id`) REFERENCES `gps` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `controllers`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `controllers` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Hash` varchar(40) DEFAULT NULL,
  `Name` text,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `Hash` (`Hash`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `gateways`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `gateways` (
  `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `Hash` varchar(40) DEFAULT NULL,
  `ConID` int(11) DEFAULT NULL,
  `Name` text,
  `GW_group` varchar(255) DEFAULT 'Default',
  `Uptime` int(11) DEFAULT '0',
  `EventTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `state` tinyint(1) unsigned DEFAULT '0',
  `private_ip` varchar(46) DEFAULT NULL,
  `last_gps_id` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `Hash` (`Hash`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `gps`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `gps` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int(10) unsigned NOT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` tinyint(1) DEFAULT '0',
  `latitude` double DEFAULT NULL,
  `longitude` double DEFAULT NULL,
  `altitude` double DEFAULT NULL,
  `track` double DEFAULT NULL,
  `speed` double DEFAULT NULL,
  `climb` double DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`,`time`),
  KEY `time` (`time`),
  CONSTRAINT `gps_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `links`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `links` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int(10) unsigned NOT NULL,
  `network` varchar(16) NOT NULL,
  `ip` varchar(46) DEFAULT NULL,
  `state` tinyint(1) unsigned DEFAULT '0',
  `bytes_tx` bigint(20) unsigned DEFAULT '0',
  `bytes_rx` bigint(20) unsigned DEFAULT '0',
  `month_tx` bigint(20) unsigned DEFAULT '0',
  `month_rx` bigint(20) unsigned DEFAULT '0',
  `quota` bigint(20) unsigned DEFAULT NULL,
  `threshold` bigint(20) DEFAULT NULL,
  `rate` bigint(20) DEFAULT NULL,
  `avg_rtt` double DEFAULT NULL,
  `avg_bw_down` double DEFAULT NULL,
  `avg_bw_up` double DEFAULT NULL,
  `updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `comment` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`,`network`),
  CONSTRAINT `links_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `passive`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `passive` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int(10) unsigned NOT NULL,
  `network` varchar(16) NOT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `interval_len` int(10) unsigned DEFAULT '0',
  `bytes_tx` bigint(20) unsigned DEFAULT '0',
  `bytes_rx` bigint(20) unsigned DEFAULT '0',
  `rate_down` double DEFAULT '0',
  `rate_up` double DEFAULT '0',
  `packets_tx` int(10) unsigned DEFAULT '0',
  `packets_rx` int(10) unsigned DEFAULT '0',
  `losses` int(10) unsigned DEFAULT '0',
  `outoforder` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`,`network`,`time`),
  KEY `time` (`time`),
  CONSTRAINT `passive_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pings`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pings` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int(10) unsigned NOT NULL,
  `network` varchar(16) NOT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `gps_id` int(10) unsigned DEFAULT NULL,
  `rtt` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`,`network`,`time`),
  KEY `gps_id` (`gps_id`),
  CONSTRAINT `pings_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `pings_ibfk_2` FOREIGN KEY (`gps_id`) REFERENCES `gps` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `state_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `state_log` (
  `node_id` int(10) unsigned NOT NULL,
  `new_state` tinyint(1) unsigned NOT NULL,
  `eventtime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`eventtime`,`node_id`),
  KEY `node_id` (`node_id`),
  CONSTRAINT `state_log_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_traffic`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_traffic` (
  `node_id` int(10) unsigned NOT NULL,
  `time` int(11) NOT NULL,
  `duration` int(11) NOT NULL,
  `client_mac` varchar(12) NOT NULL,
  `bytes_sent` int(11) NOT NULL,
  `bytes_received` int(11) NOT NULL,
  `packets_sent` int(11) NOT NULL,
  `packets_received` int(11) NOT NULL,
  PRIMARY KEY (`node_id`,`client_mac`,`time`),
  CONSTRAINT `user_traffic_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-08-04 15:07:06
