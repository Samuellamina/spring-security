package samuel.tutorials.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import samuel.tutorials.springsecurity.domain.AppUser;

public interface AppUserRepository extends JpaRepository
        <AppUser, Long> {
    AppUser findByUsername(String username);
}
