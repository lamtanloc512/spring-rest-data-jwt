package com.devcamp.utils;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class UserPrincipal extends User {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public UserPrincipal(String username, String password, boolean enabled, boolean accountNonExpired,
	    boolean credentialsNonExpired, boolean accountNonLocked,
	    Collection<? extends GrantedAuthority> authorities) {
	super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    public UserPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
	super(username, password, authorities);
    }

}
