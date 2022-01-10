package root.service;

import root.model.dto.UserDto;

public interface UserAuthService {
    String create(UserDto userDto);
}
