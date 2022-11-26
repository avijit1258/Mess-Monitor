package com.messmonitor.serviceuser.repository;

import com.messmonitor.serviceuser.entity.Role;
import com.messmonitor.serviceuser.utils.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
