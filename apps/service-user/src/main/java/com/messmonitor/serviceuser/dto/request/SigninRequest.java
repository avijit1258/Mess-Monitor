package com.messmonitor.serviceuser.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Getter
@Setter
@NoArgsConstructor
public class SigninRequest {

    @NotBlank
    private String username;

    @NotBlank
    private String password;

}
