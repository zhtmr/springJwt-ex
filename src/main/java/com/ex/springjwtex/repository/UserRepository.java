package com.ex.springjwtex.repository;


import com.ex.springjwtex.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
  Boolean existsByUsername(String username);
}
