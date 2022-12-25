INSERT INTO `user` (`user_no`, `user_id`) VALUES ('de725888-8436-11ed-98cf-d8bbc1f7ab35', 'jd0419');
INSERT INTO `user` (`user_no`, `user_id`) VALUES ('5cbae64a-8437-11ed-98cf-d8bbc1f7ab35', 'mj0129');
INSERT INTO `user` (`user_no`, `user_id`) VALUES ('18d379d4-8437-11ed-98cf-d8bbc1f7ab35', 'we');

INSERT INTO `profile` (`profile_id`, `user_no`, `name`, `nickname`, `introduction`, `join_date`, `update_date`) VALUES (7, 'de725888-8436-11ed-98cf-d8bbc1f7ab35', '김정도', '라이징브레어', '안녕하세요!', '2022-12-25 18:31:06', '2022-12-25 18:31:06');
INSERT INTO `profile` (`profile_id`, `user_no`, `name`, `nickname`, `introduction`, `join_date`, `update_date`) VALUES (9, '18d379d4-8437-11ed-98cf-d8bbc1f7ab35', '위준성', '위두', '안뇽', '2022-12-25 18:32:44', '2022-12-25 18:32:44');
INSERT INTO `profile` (`profile_id`, `user_no`, `name`, `nickname`, `introduction`, `join_date`, `update_date`) VALUES (11, '5cbae64a-8437-11ed-98cf-d8bbc1f7ab35', '김민지', '소피마르소', '안녕 ~ !', '2022-12-25 18:34:38', '2022-12-25 18:34:38');

INSERT INTO `authenctication` (`authenctication_id`, `user_no`, `role`, `gather_agree`, `cell_phone`, `birthday`, `sex`) VALUES (11, '5cbae64a-8437-11ed-98cf-d8bbc1f7ab35', '관리자', 1, '01031051667', '2003-01-29', 1);
INSERT INTO `authenctication` (`authenctication_id`, `user_no`, `role`, `gather_agree`, `cell_phone`, `birthday`, `sex`) VALUES (9, '18d379d4-8437-11ed-98cf-d8bbc1f7ab35', '관리자', 0, '01094414141', '1994-04-01', 0);
INSERT INTO `authenctication` (`authenctication_id`, `user_no`, `role`, `gather_agree`, `cell_phone`, `birthday`, `sex`) VALUES (7, 'de725888-8436-11ed-98cf-d8bbc1f7ab35', '관리자', 1, '01089931667', '1998-04-19', 0);

INSERT INTO `password` (`password_id`, `user_no`, `PASSWORD`, `refresh_token`, `update_date`) VALUES (7, 'de725888-8436-11ed-98cf-d8bbc1f7ab35', '$2b$12$cBEGNrWukNGkk/vLIJ/tEuj3PrLtxEhN9Q/s2c7O2PNVe4trKoUxy', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzE5NjEwNDYsInVzZXJJRCI6ImpkMDQxOSJ9.0SfUuGvpaeqLvIJNxtZPZx3L5oUug7qS-_n6C7WN9pk', '2022-12-25 18:34:56');
INSERT INTO `password` (`password_id`, `user_no`, `PASSWORD`, `refresh_token`, `update_date`) VALUES (9, '18d379d4-8437-11ed-98cf-d8bbc1f7ab35', '$2b$12$hVxbjWzaXtbvns7p8mFCKOLc5emO0g/gwzwzGUlgrJ.tXl3fzLPW2', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzE5NjA5MTksInVzZXJJRCI6IndlIn0.HvUvTcDenTMM9aSux_hjQPQMhNhfu8a7Qbuz5ZA0EJo', '2022-12-25 18:32:49');
INSERT INTO `password` (`password_id`, `user_no`, `PASSWORD`, `refresh_token`, `update_date`) VALUES (11, '5cbae64a-8437-11ed-98cf-d8bbc1f7ab35', '$2b$12$xFB0b1rsKKDVFSbRq8NjHOQN1slTdX6DajN0huiWgTvy0T.ZWeEya', NULL, '2022-12-25 18:34:38');