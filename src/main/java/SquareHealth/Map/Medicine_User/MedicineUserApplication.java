package SquareHealth.Map.Medicine_User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import java.security.Key;
import java.util.Date;


import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@SpringBootApplication
public class MedicineUserApplication {

	public static void main(String[] args) {
		SpringApplication.run(MedicineUserApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder getBCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
}

@RestController
class BasicController {

	@Autowired
	private JwtService jwtService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("login")
	public ResponseEntity<String> login(@RequestBody LoginRequestDTO loginRequestDTO) {

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword());
		authenticationManager.authenticate(token);
		String jwt = jwtService.buildToken(loginRequestDTO.getUsername());
		return ResponseEntity.ok(jwt);
	}

	@GetMapping("/hello")
	public ResponseEntity<String> get(){
		return ResponseEntity.ok("Hello");
	}
}

@NoArgsConstructor
class LoginRequestDTO {
	private String username;
	private String password;

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}
}


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfiguration {

	@Autowired
	private JwtTokenFilter jwtTokenFilter;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	@Autowired
	public void configurePasswordEncoder(AuthenticationManagerBuilder builder) throws Exception {
		builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder);
		return authenticationProvider;
	}

	@Bean
	public AuthenticationManager getAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}


	@Bean
	protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(req -> req
						.requestMatchers("/login").permitAll()
						.requestMatchers("/map", "/map/{locationId}").authenticated()
				)

				.sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
				.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}
}


/*
 * Custom filter will run once per request. We add this to Filter Chain
 */

// todo : Authorization Format --> Bearer-space-(token)
@Component
class JwtTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtService jwtService;

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest httpServletRequest,
									@NonNull HttpServletResponse httpServletResponse,
									@NonNull FilterChain filterChain) throws ServletException, IOException {

		final String authorizationHeader = httpServletRequest.getHeader("Authorization");

		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer")){
			filterChain.doFilter(httpServletRequest, httpServletResponse);
			return;
		}

		final String token = authorizationHeader.split(" ")[1].trim();
		if (!jwtService.validate(token)) {
			filterChain.doFilter(httpServletRequest, httpServletResponse);
			return;
		}

		String username = jwtService.getUsername(token);
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
		authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
		SecurityContextHolder.getContext().setAuthentication(authToken);

		filterChain.doFilter(httpServletRequest, httpServletResponse);
	}
}


/*
 * Custom UserDetailsService implementation
 */
@Service
class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Map<String, String> users = new HashMap<>();
		users.put("farhan", passwordEncoder.encode("123"));
		if (users.containsKey(username))
			return new User(username, users.get(username), new ArrayList<>());
		throw new UsernameNotFoundException(username);
	}
}

@Service
class JwtService {

	private static final int expireInMs = 300 * 1000;
	private final static Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

	public String buildToken(String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuer("farhan ahmed")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + expireInMs))
				.signWith(key)
				.compact();
	}
	public boolean validate(String token) {
		return getUsername(token) != null && isExpired(token);
	}

	public String getUsername(String token) {
		Claims claims = getClaims(token);
		return claims.getSubject();
	}

	public boolean isExpired(String token) {
		Claims claims = getClaims(token);
		return claims.getExpiration().after(new Date(System.currentTimeMillis()));
	}

	private Claims getClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
}
