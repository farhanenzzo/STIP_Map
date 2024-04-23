create database square_map;
use square_map;

CREATE TABLE bd_location (
    id BIGINT AUTO_INCREMENT,
    name VARCHAR(100) UNIQUE,
    lat DOUBLE NOT NULL,
    lng DOUBLE NOT NULL,
    CONSTRAINT pk_bd_location PRIMARY KEY (id)
);

INSERT INTO bd_location (name, lat, lng) VALUES
('Gulshan1', 23.7806615, 90.4112899),
('Banani', 23.7947552, 90.3954059),
('Dhanmondi', 23.7470303, 90.3655623),
('Mirpur1', 23.7945624, 90.3435587),
('Uttara', 23.8766322, 90.3576884);, 90.3915);

