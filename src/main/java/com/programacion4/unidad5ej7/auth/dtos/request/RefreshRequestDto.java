package com.programacion4.unidad5ej7.auth.dtos.request;

import jakarta.validation.constraints.NotBlank;

public record RefreshRequestDto(
        @NotBlank(message = "El refresh token es obligatorio")
        String refreshToken
) {
}