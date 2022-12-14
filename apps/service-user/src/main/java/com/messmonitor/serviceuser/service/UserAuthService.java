package com.messmonitor.serviceuser.service;

import com.messmonitor.serviceuser.dto.request.ChangePasswordRequestDTO;
import com.messmonitor.serviceuser.dto.request.SignUpRequest;
import com.messmonitor.serviceuser.dto.response.MessageResponse;
import com.messmonitor.serviceuser.entity.Role;
import com.messmonitor.serviceuser.entity.User;
import com.messmonitor.serviceuser.repository.RoleRepository;
import com.messmonitor.serviceuser.repository.UserRepository;
import com.messmonitor.serviceuser.utils.ERole;
import com.messmonitor.serviceuser.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.ResourceAccessException;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserAuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;


    public MessageResponse SignUp(SignUpRequest signUpRequest) {

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                true);

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        user.setActive(true);
        userRepository.save(user);
        return new MessageResponse("User created successfully!");
    }

    @SneakyThrows
    public String changeUserPassword(ChangePasswordRequestDTO changePasswordDTO, Long user_id) throws Exception {

        User user = userRepository.findById(user_id)
                .orElseThrow(() -> new ResourceAccessException("User not found"));

        if (!encoder.matches(changePasswordDTO.getOld_password(), user.getPassword())) {
            throw new ResourceAccessException("Password is incorrect!");
        } else if (changePasswordDTO.getOld_password().equals(changePasswordDTO.getNew_password())) {
            throw new ResourceAccessException("Old password can not be same as new password!");
        } else if (!changePasswordDTO.getNew_password().equals(changePasswordDTO.getConfirm_new_password())) {
            throw new ResourceAccessException("Confirm password and new password must be same!");
        }

        user.setPassword(encoder.encode(changePasswordDTO.getConfirm_new_password()));
        userRepository.save(user);

        return Status.SUCCESS.getValue();
    }

    @SneakyThrows
    public void archivedUser(Long user_id) throws Exception {

        User user = userRepository.findById(user_id)
                .orElseThrow(() -> new ResourceAccessException("User not found"));

        user.setActive(false);
        userRepository.save(user);
    }

}
