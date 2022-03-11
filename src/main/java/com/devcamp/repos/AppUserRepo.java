package com.devcamp.repos;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.devcamp.entity.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {
	Optional<AppUser> findByUsername(String username);
}
