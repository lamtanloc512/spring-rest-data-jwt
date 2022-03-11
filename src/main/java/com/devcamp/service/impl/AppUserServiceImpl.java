package com.devcamp.service.impl;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.devcamp.entity.AppUser;
import com.devcamp.repos.AppUserRepo;
import com.devcamp.service.IAppUserService;
import com.devcamp.utils.UserPrincipal;

@Service
public class AppUserServiceImpl implements IAppUserService {
	@Autowired
	private AppUserRepo appUserRepo;

	@Override
	public AppUser saveUser(AppUser user) {
		return appUserRepo.save(user);
	}

	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		var _userExist = appUserRepo.findByUsername(username);
		if (_userExist.isPresent()) {
			var password = _userExist.get().getPassword();
			Collection<SimpleGrantedAuthority> authories = new ArrayList<>();

			_userExist.get().getRole().forEach(role -> authories
					.add(new SimpleGrantedAuthority(role.getName())));

			UserPrincipal user = new UserPrincipal(username, password,
					authories);
			return user;
		} else {
			throw new UsernameNotFoundException(
					"Cannot find user with username: " + username);
		}

	}

}
