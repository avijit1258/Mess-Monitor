package com.messmonitor.serviceuser.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
public class ChangePasswordRequestDTO {

    @NotBlank
    @Size(min = 6, max = 128)
    private String old_password;

    @NotBlank
    @Size(min = 6, max = 128)
    private String new_password;

    @NotBlank
    @Size(min = 6, max = 128)
    private String confirm_new_password;
}
