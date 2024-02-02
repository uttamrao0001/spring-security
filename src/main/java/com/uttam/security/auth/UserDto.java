package com.uttam.security.auth;

import com.uttam.security.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

  private String firstname;
  private String lastname;
  private String email;
  private String password;
  private Role role;
  private String confirmPassword;

}
