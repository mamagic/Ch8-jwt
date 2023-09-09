package tacos.web.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tacos.User;
import tacos.data.UserRepository;
import tacos.security.RegistrationForm;

@RestController
@RequestMapping("/registry")                      
public class RegistryController {
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	PasswordEncoder passwordEncoder;

	@PostMapping
	public User registry(@RequestBody User user) {
		return userRepository.save(new RegistrationForm().toUser(passwordEncoder, user));
	}
}
