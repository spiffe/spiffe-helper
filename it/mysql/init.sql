CREATE USER client@'%' REQUIRE SUBJECT '/C=US/O=SPIRE/CN=client/x500UniqueIdentifier=1fab30ffbcbbcae9ec2ddfe24442f9d2';

CREATE DATABASE test_db;
USE test_db;

CREATE TABLE mail (id BIGINT AUTO_INCREMENT PRIMARY KEY, mail VARCHAR(256));
INSERT INTO mail(mail) VALUES ('test@user.com');

GRANT ALL PRIVILEGES ON test_db.* TO client@'%';
FLUSH PRIVILEGES;
