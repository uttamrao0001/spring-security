package com.uttam.security.user;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    // Additional methods if needed
    Optional<Role> findByName(String name);

}
