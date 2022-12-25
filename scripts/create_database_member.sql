create database member;
use member;

create table user (
	user_no binary(36),
	user_id varchar(20) not null unique,
	
	primary key (user_no)
);

create table profile (
	profile_id int unsigned primary key auto_increment,
	user_no binary(36),
	name varchar(20) not null,
	nickname varchar(12),
	introduction varchar(50),
	join_date datetime not null default current_timestamp,
	update_date datetime not null default current_timestamp on update current_timestamp,
	
	foreign key (user_no) references user (user_no) on update cascade on delete cascade
);

create table authenctication (
	authenctication_id int unsigned primary key auto_increment,
	user_no binary(36),
	role varchar(3) default "관리자",
	gather_agree tinyint unsigned,
	cell_phone varchar(128),
	birthday varchar(128),
	sex tinyint unsigned,
	
	foreign key (user_no)
   references user (user_no) on update cascade on delete cascade
);