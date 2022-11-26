package com.messmonitor.serviceuser.controller;

import com.messmonitor.serviceuser.dto.request.SignUpRequest;
import com.messmonitor.serviceuser.dto.request.SigninRequest;
import com.messmonitor.serviceuser.dto.response.MessageResponse;
import com.messmonitor.serviceuser.dto.response.SignUpResponse;
import com.messmonitor.serviceuser.repository.RoleRepository;
import com.messmonitor.serviceuser.repository.UserRepository;
import com.messmonitor.serviceuser.security.JwtUtils;
import com.messmonitor.serviceuser.service.UserAuthService;
import com.messmonitor.serviceuser.service.impl.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private UserAuthService authService;

    @Autowired
    private JwtUtils jwtUtils;

    @Value("${user.app.jwtSecret}")
    private String jwtSecret;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody SigninRequest signinRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signinRequest.getUsername(), signinRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new SignUpResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {

        MessageResponse response = authService.SignUp(signUpRequest);

        return ResponseEntity.ok(response);
    }

  /*  @PostMapping("users/change-password")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequestDTO changePasswordDTO) throws Exception {

            String header = jwtUtils.getTokenWithBearerFromHeader("AUTHORIZATION");
            String token =  jwtUtils.parseToken(header,"Bearer ");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
           *//* Long user_id = auth.getPrincipal()s()
                    //Long.valueOf(Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecret)).parseClaimsJws(token).getBody().getId());

            String status = authService.changeUserPassword(changePasswordDTO, user_id);*//*

            return ResponseEntity.ok(
                    "Changed password succesfully!"
            );

    }*/

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {

        String header = jwtUtils.getTokenWithBearerFromHeader("AUTHORIZATION");
        String token = jwtUtils.parseToken(header, "Bearer ");
        String logoutOk = jwtUtils.getExpiryFromJwt(token);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        return "logout successfully!";
    }

    @DeleteMapping("/archive/{userId}")
    public ResponseEntity<?> archiveUser(@PathVariable("userId") Long userId) throws Exception {

            authService.archivedUser(userId);
            return ResponseEntity.ok("user archived successfully!");

    }

}