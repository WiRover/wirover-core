CREATE USER 'wirover'@'localhost' IDENTIFIED BY 'wirover';

GRANT ALL PRIVILEGES ON monitoring.* TO 'wirover'@'%';
GRANT ALL PRIVILEGES ON wiroot.* TO 'wirover'@'%';

GRANT ALL PRIVILEGES ON monitoring.* TO 'wirover'@'localhost';
GRANT ALL PRIVILEGES ON wiroot.* TO 'wirover'@'localhost';
