package samuel.tutorials.springsecurity.service;

import samuel.tutorials.springsecurity.domain.Role;
import samuel.tutorials.springsecurity.domain.AppUser;

import java.util.List;

public interface AppUserService {
    AppUser saveUSer(AppUser user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String rolename);

    AppUser getUser(String username);

    List<AppUser> getUsers();
}
