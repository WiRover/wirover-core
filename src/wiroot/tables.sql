create table if not exists uniqueid (
    id      smallint(5) unsigned not null auto_increment,
    hwaddr  char(12) not null,
    name    varchar(32) default null,

    primary key (id),
    unique key (hwaddr)
) engine=InnoDB default charset=utf8;

