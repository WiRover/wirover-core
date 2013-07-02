CREATE TABLE `active_measurements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `latitude` float DEFAULT NULL,
  `longitude` float DEFAULT NULL,
  `uploadRate` float DEFAULT NULL,
  `downloadRate` float DEFAULT NULL,
  `interface` varchar(32) DEFAULT NULL,
  `downloadTimePreTransfer` float DEFAULT NULL,
  `uploadTimePreTransfer` float DEFAULT NULL,
  `fileSize` int(10) unsigned DEFAULT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `node_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `gateways` (
  `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `Hash` varchar(40) DEFAULT NULL,
  `NodeID` int(11) NOT NULL DEFAULT '0',
  `ConID` int(11) DEFAULT NULL,
  `Name` text,
  `Uptime` int(11) DEFAULT '0',
  `EventTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `state` tinyint(1) unsigned DEFAULT '0',
  `private_ip` varchar(46) DEFAULT NULL,
  `last_gps_id` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `Hash` (`Hash`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;

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
  UNIQUE KEY `node_id` (`node_id`,`time`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

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
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

CREATE TABLE `client_traffic` (
  `client_id` int(11) DEFAULT NULL,
  `node_id` int(11) DEFAULT NULL,
  `insert_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `duration` int(11) DEFAULT NULL,
  `bytes_sent` int(11) DEFAULT NULL,
  `bytes_recvd` int(11) DEFAULT NULL,
  `packets_sent` int(11) DEFAULT NULL,
  `packets_recvd` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hwaddr` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `constatus` (
  `conID` int(11) NOT NULL DEFAULT '0',
  `uptime` float DEFAULT NULL,
  `cpu` float DEFAULT NULL,
  `disk` float DEFAULT NULL,
  `ram` float DEFAULT NULL,
  `min1` float DEFAULT NULL,
  `min5` float DEFAULT NULL,
  `min15` float DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `wiroot` tinyint(4) DEFAULT NULL,
  `wicontroller` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`conID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `controllers` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Hash` varchar(40) DEFAULT NULL,
  `Name` text,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `Hash` (`Hash`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;

CREATE TABLE `gwdata` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `GatewayID` int(11) DEFAULT NULL,
  `Min1Load` float DEFAULT NULL,
  `Min5Load` float DEFAULT NULL,
  `Min15Load` float DEFAULT NULL,
  `TopTask` text,
  `TotalTasks` int(11) DEFAULT NULL,
  `RunningTasks` int(11) DEFAULT NULL,
  `DiskUsed` float DEFAULT NULL,
  `RamUsed` float DEFAULT NULL,
  `status` tinyint(1) DEFAULT NULL,
  `extra` text,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;


CREATE TABLE `links` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `GatewayID` int(10) unsigned NOT NULL,
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
  UNIQUE KEY `node_id` (`GatewayID`,`network`)
) ENGINE=InnoDB AUTO_INCREMENT=45489 DEFAULT CHARSET=utf8;

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
  CONSTRAINT `passive_ibfk_1` FOREIGN KEY (`node_id`) REFERENCES `gateways` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

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
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

CREATE VIEW `gwstatus` AS select `gwdata`.`ID` AS `ID`,`gwdata`.`GatewayID` AS `GatewayID`,if((timestampdiff(MINUTE,`gwdata`.`time`,now()) > 7),0,1) AS `online`,if((`gwdata`.`DiskUsed` > 0.8),0,1) AS `diskok`,if((`gwdata`.`RamUsed` > 0.8),0,1) AS `ramok`,if((`gwdata`.`Min15Load` > 0.8),0,1) AS `cpuok`,if(((`gwdata`.`DiskUsed` > 0.8) or (`gwdata`.`RamUsed` > 0.8) or (`gwdata`.`Min15Load` > 0.8)),0,1) AS `healthy`,if((`gwdata`.`status` <> 1),0,1) AS `reachable` from `gwdata`;
