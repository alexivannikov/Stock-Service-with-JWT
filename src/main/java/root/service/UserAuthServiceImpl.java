package root.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import root.model.dto.UserDto;
import root.model.entity.UserEntity;
import root.model.repository.UserRepository;

@Component
@RequiredArgsConstructor
public class UserAuthServiceImpl implements UserAuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public String create(UserDto userDto) {
        UserEntity userEntity = new UserEntity();
        userEntity.setLogin(userDto.getLogin());
        userEntity.setPassword(passwordEncoder.encode(userDto.getPassword()));
        userEntity.setRole("BASE");

        return userRepository.save(userEntity).getLogin();
    }
}
