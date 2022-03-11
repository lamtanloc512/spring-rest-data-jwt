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
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	var _userExist = appUserRepo.findByUsername(username);
	Collection<SimpleGrantedAuthority> authories = new ArrayList<>();
	if (_userExist == null) {
	    throw new UsernameNotFoundException("Username not found");
	} else {
	    _userExist.getRole().forEach(role -> authories.add(new SimpleGrantedAuthority(role.getName())));
	}
	return new UserPrincipal(_userExist.getUsername(), _userExist.getPassword(), authories);
    }

}
