package samuel.tutorials.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import samuel.tutorials.springsecurity.domain.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
