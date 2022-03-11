package com.devcamp.repos;

import org.springframework.data.jpa.repository.JpaRepository;

import com.devcamp.entity.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

}
