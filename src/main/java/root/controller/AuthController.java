package root.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import root.model.dto.UserDto;
import root.security.jwt.JWTProvider;
import root.service.UserAuthService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserAuthService userAuthService;
    private final JWTProvider jwtProvider;

    @Autowired
    private final AuthenticationManager authenticationManager;

    public AuthController(UserAuthService userAuthService, JWTProvider jwtProvider, AuthenticationManager authenticationManager) {
        this.userAuthService = userAuthService;
        this.jwtProvider = jwtProvider;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/create")
    public String createUserAuth(@RequestBody UserDto userDto) {
        return userAuthService.create(userDto);
    }

    @GetMapping("/login")
    public ResponseEntity <Void> login(@RequestHeader(HttpHeaders.AUTHORIZATION) String logpass) {
        String[] logpassArray = new String(Base64.getDecoder().decode(logpass.substring(6)), StandardCharsets.UTF_8).split(":");

        String login = logpassArray[0];
        String password = logpassArray[1];

        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login, password));
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        String jwtToken = jwtProvider.generateJWT(login);
        return ResponseEntity
                .ok()
                .header("access_token", jwtToken)
                .build();
    }

}
