package tn.cyn.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import tn.cyn.entities.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
	public AppUser findOneByUsername(String username);
}
