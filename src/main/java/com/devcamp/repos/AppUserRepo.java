package com.devcamp.repos;

import org.springframework.data.jpa.repository.JpaRepository;

import com.devcamp.entity.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
