package com.devcamp.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.devcamp.entity.AppUser;

public interface IAppUserService extends UserDetailsService {
	AppUser saveUser(AppUser user);
}
