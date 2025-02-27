package com.esprit.project.repositories;

import com.esprit.project.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    //This methode will be used for authentication
    Optional<User> findByUsername(String username);
}
