package co.app.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import co.app.models.dto.AuthCreateUserRequest;
import co.app.models.dto.AuthLoginRequest;
import co.app.models.dto.AuthResponse;
import co.app.models.entity.RolEntity;
import co.app.models.entity.RolEnum;
import co.app.models.entity.UsuarioEntity;
import co.app.repository.RolRepository;
import co.app.repository.UsuarioRepository;
import co.app.util.JwtUtils;

@Service
public class UsuarioServiceImpl implements UserDetailsService {

    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final UsuarioRepository usuarioRepository;
    private final RolRepository roleRepository;

    public UsuarioServiceImpl(JwtUtils jwtUtils, PasswordEncoder passwordEncoder, UsuarioRepository usuarioRepository,
            RolRepository roleRepository) {
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
        this.usuarioRepository = usuarioRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {

        UsuarioEntity userEntity = usuarioRepository.findUserEntityByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El usuario " + username + " no existe."));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        userEntity.getRoles().forEach(
                role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRolEnum().name()))));

        userEntity.getRoles().stream().flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        return new User(userEntity.getUsername(), userEntity.getPassword(), userEntity.isEnabled(),
                userEntity.isAccountNoExpired(), userEntity.isCredentialNoExpired(), userEntity.isAccountNoLocked(),
                authorityList);
    }

    public AuthResponse createUser(AuthCreateUserRequest createRoleRequest) {

        String username = createRoleRequest.username();
        String password = createRoleRequest.password();
        List<String> rolesRequest = createRoleRequest.roleRequest().roleListName();

        List<RolEnum> rolEnums = rolesRequest.stream()
                .map(roleName -> {
                    try {
                        return RolEnum.valueOf(roleName);
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("Role name " + roleName + " is not valid.", e);
                    }
                })
                .collect(Collectors.toList());

        Set<RolEntity> roleEntityList = roleRepository.findRolEntitiesByRolEnumIn(rolEnums).stream()
                .collect(Collectors.toSet());

        if (roleEntityList.isEmpty()) {
            throw new IllegalArgumentException("The roles specified does not exist.");
        }

        UsuarioEntity userEntity = UsuarioEntity.builder().username(username).password(passwordEncoder.encode(password))
                .roles(roleEntityList).isEnabled(true).accountNoLocked(true).accountNoExpired(true)
                .credentialNoExpired(true).build();

        UsuarioEntity userSaved = usuarioRepository.save(userEntity);

        ArrayList<SimpleGrantedAuthority> authorities = new ArrayList<>();

        userSaved.getRoles()
                .forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRolEnum().name()))));

        userSaved.getRoles().stream().flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getName())));

        Authentication authentication = new UsernamePasswordAuthenticationToken(userSaved, null, authorities);

        String accessToken = jwtUtils.createToken(authentication);

        return new AuthResponse(username, "User created successfully", accessToken, true);
    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {

        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtils.createToken(authentication);
        return new AuthResponse(username, "Usuario logueado exitosamente", accessToken, true);
    }

    public Authentication authenticate(String username, String password) {
        UserDetails userDetails = this.loadUserByUsername(username);

        if (userDetails == null) {
            throw new BadCredentialsException("Usuario o contraseña invalidos");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Incorrect Password");
        }

        return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
    }
}
