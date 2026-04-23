package com.programacion4.unidad5ej7.auth.services.impl;

import com.programacion4.unidad5ej7.auth.dtos.request.LoginRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RegisterRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.response.AuthResponseDto;
import com.programacion4.unidad5ej7.auth.jwt.JwtProperties;
import com.programacion4.unidad5ej7.auth.jwt.JwtService;
import com.programacion4.unidad5ej7.auth.models.UserEntity;
import com.programacion4.unidad5ej7.auth.models.UserRole;
import com.programacion4.unidad5ej7.auth.repository.UserRepository;
import com.programacion4.unidad5ej7.config.exceptions.InvalidCredentialsException;
import com.programacion4.unidad5ej7.config.exceptions.UserAlreadyExistsException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.AllArgsConstructor;
import com.programacion4.unidad5ej7.auth.services.interfaces.IAuthService;

import java.util.List;

@Service
@AllArgsConstructor
public class AuthService implements IAuthService {

	private static final String TOKEN_TYPE_BEARER = "Bearer";

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;
	private final JwtProperties jwtProperties;


	/**
	 * Registro: rechaza username duplicado, codifica la contraseña y guarda el usuario con rol por defecto.
	 */
	@Transactional
	@Override
	public void register(RegisterRequestDto request) {
		if (userRepository.existsByUsername(request.username())) {
			throw new UserAlreadyExistsException();
		}
		UserEntity user = UserEntity.builder()
				.username(request.username())
				.password(passwordEncoder.encode(request.password()))
				.role(UserRole.ROLE_USER)
				.build();
		userRepository.save(user);
	}

	/**
	 * Login: el {@link AuthenticationManager} valida credenciales; si son correctas se emite un JWT con los
	 * mismos nombres de rol que {@link UserDetails#getAuthorities()}.
	 */
	@Override
	public AuthResponseDto login(LoginRequestDto request) {
		try {
			Authentication authentication = authenticationManager.authenticate(
					UsernamePasswordAuthenticationToken.unauthenticated(
							request.username(),
							request.password()
					)
			);

			UserDetails principal = (UserDetails) authentication.getPrincipal();

			var roles = principal.getAuthorities()
					.stream()
					.map(GrantedAuthority::getAuthority)
					.toList();

			String accessToken = jwtService.generateAccessToken(principal.getUsername(), roles);
			String refreshToken = jwtService.generateRefreshToken(principal.getUsername());

			return new AuthResponseDto(
					accessToken,
					refreshToken,
					TOKEN_TYPE_BEARER,
					jwtProperties.accessExpirationMs()
			);

		} catch (BadCredentialsException e) {
			throw new InvalidCredentialsException();
		}
	}

	public AuthResponseDto refresh(String refreshToken) {

		var claimsOpt = jwtService.parseValidClaims(refreshToken);

		if (claimsOpt.isEmpty()) {
			throw new InvalidCredentialsException();
		}

		String username = claimsOpt.get().getSubject();

		UserEntity user = userRepository.findByUsername(username)
				.orElseThrow(InvalidCredentialsException::new);

		String accessToken = jwtService.generateAccessToken(
				user.getUsername(),
				List.of(user.getRole().name())
		);

		return new AuthResponseDto(
				accessToken,
				refreshToken,
				TOKEN_TYPE_BEARER,
				jwtProperties.accessExpirationMs()
		);
	}
}
