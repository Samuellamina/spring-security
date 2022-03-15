package samuel.tutorials.springsecurity;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import samuel.tutorials.springsecurity.domain.AppUser;
import samuel.tutorials.springsecurity.domain.Role;
import samuel.tutorials.springsecurity.service.AppUserService;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(AppUserService appUserService) {
		return args -> {
			appUserService.saveRole(new Role(null, "ROLE_USER"));
			appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
			appUserService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			appUserService.saveUSer(new AppUser(null, "katy aubrurn", "katy", "1234", new ArrayList<>()));
			appUserService.saveUSer(new AppUser(null, "james bay", "james", "1234", new ArrayList<>()));
			appUserService.saveUSer(new AppUser(null, "arn xavi", "arn", "1234", new ArrayList<>()));

			appUserService.addRoleToUser("katy", "ROLE_USER");
			appUserService.addRoleToUser("james", "ROLE_USER, ROLE_ADMIN");
			appUserService.addRoleToUser("arn", "ROLE_USER, ROLE_SUPER_ADMIN");
		};
	}

}
