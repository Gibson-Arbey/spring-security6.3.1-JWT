package co.app.models.dto;

import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
public record AuthCreateRoleRequest(
        @Size(max = 3, message = "El usuario no puede tener más de 3 roles") List<String> roleListName) {
}
