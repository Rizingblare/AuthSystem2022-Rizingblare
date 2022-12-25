create database auth;
use auth;

create table password (
	password_id int unsigned primary key auto_increment,
	user_no binary(36),
	password varchar(128) not null,
	refresh_token varchar(256) null,
	update_date datetime not null default current_timestamp on update current_timestamp,
	
	foreign key (user_no) references member.user(user_no) on update cascade on delete cascade
);