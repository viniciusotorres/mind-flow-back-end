package com.example.mindflow.controller;
import com.example.mindflow.model.Usuario;
import com.example.mindflow.negocios.UsuarioLogadoNegocio;
import com.example.mindflow.repositoy.UsuarioRepository;
import com.example.mindflow.service.AuthService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

import static org.yaml.snakeyaml.tokens.Token.ID.Key;


@RestController
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {
    private final UsuarioRepository usuarioRepository;
    private final UsuarioLogadoNegocio usuarioLogadoNegocio;

    private static final long EXPIRATION_TIME = 864_000_000;



    @Autowired

    private AuthService tokenBlackList;

    public AuthController(
            UsuarioRepository usuarioRepository,
            UsuarioLogadoNegocio usuarioLogadoNegocio) {
        this.usuarioRepository = usuarioRepository;
        this.usuarioLogadoNegocio = usuarioLogadoNegocio;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Usuario usuario){
        if (this.usuarioLogadoNegocio.verificaSeUsuarioERegistrado(usuario)) {
            String token = gerarTokenJWT(usuario.getEmail());
            return ResponseEntity.ok(Map.of("message", "Login bem-sucedido!", "token", token));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Credenciais inválidas"));
        }
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> requestBody) {
        try {
            String token = requestBody.get("token");

            if (token != null && !token.isBlank() && !tokenBlackList.isTokenBlacklisted(token)) {
                tokenBlackList.addToBlacklist(token);
                return ResponseEntity.ok(Map.of("message", "Logout bem-sucedido!"));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Token já revogado"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Erro interno no servidor"));
        }
    }

    private String gerarTokenJWT(String email) {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String tokenGerado = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
        return tokenGerado;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Usuario usuario) {
        if(usuarioRepository.findByEmail(usuario.getEmail()).isPresent()){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email já registrado.");
        }
        usuarioRepository.save(usuario);
        return ResponseEntity.ok("Registro bem-sucedido!");

    }
}
