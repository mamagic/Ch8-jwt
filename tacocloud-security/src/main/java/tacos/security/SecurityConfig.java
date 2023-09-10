package tacos.security;

import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tomcat.util.json.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tacos.security.jwt.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final UserDetailsService userService;
	private final JsonLoginProcessFilter jsonLoginProcessFilter;
	private final ObjectMapper objectMapper;
	private final AuthenticationManager authenticationManager;

	//jwt
	private final JwtFilter jwtFilter;
	private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

	private final TokenProvider tokenProvider;

	public SecurityConfig(@Lazy UserDetailsService userService,
						  @Lazy JsonLoginProcessFilter jsonLoginProcessFilter,
						  ObjectMapper objectMapper,
						  JwtAccessDeniedHandler jwtAccessDeniedHandler,
						  JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
						  JwtFilter jwtFilter,
						  @Lazy AuthenticationManager authenticationManager,
						  TokenProvider tokenProvider
						  ) {
		this.userService = userService;
		this.jsonLoginProcessFilter = jsonLoginProcessFilter;
		this.objectMapper = objectMapper;
		this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
		this.jwtFilter = jwtFilter;
		this.authenticationManager = authenticationManager;
		this.tokenProvider = tokenProvider;
	}
	

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {


		httpSecurity
				.authorizeHttpRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다.
				.requestMatchers(HttpMethod.OPTIONS).permitAll() // needed for Angular/CORS
				.requestMatchers(HttpMethod.POST, "/api/ingredients").permitAll()
				.requestMatchers("/design", "/orders/**", "/login").permitAll() // 로그인 api
				// .access("hasRole('ROLE_USER')")
				.requestMatchers(HttpMethod.PATCH, "/ingredients").permitAll() // 회원가입 api
				.requestMatchers("/**").permitAll()

				.and()
				.csrf().disable() // 외부 POST 요청을 받아야하니 csrf는 꺼준다.
				.cors().configurationSource(corsConfigurationSource())

				// 아래부분은 따로 필터를 만듬
				// .and()
				// .formLogin()
				// .usernameParameter("username")
				// .passwordParameter("password")
				// .loginProcessingUrl("/login")
				// .defaultSuccessUrl("/")

				.and().httpBasic().realmName("Taco Cloud")
				.and().logout().logoutSuccessUrl("/")

				// Allow pages to be loaded in frames from the same origin; needed for
				// H2-Console
				.and().headers().frameOptions().sameOrigin();

		httpSecurity
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(jsonLoginProcessFilter, UsernamePasswordAuthenticationFilter.class)
				.authenticationProvider(daoAuthenticationProvider());
//				.exceptionHandling()
//				.accessDeniedHandler(jwtAccessDeniedHandler)
//				.authenticationEntryPoint(jwtAuthenticationEntryPoint);
//				.and()
//				.apply(new JwtSecurityConfig(tokenProvider));

//		httpSecurity
//				.addFilter(jsonLoginProcessFilter)
//				.authenticationProvider(daoAuthenticationProvider());
//				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션을 사용하지 않겠다


		return httpSecurity.build();
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() throws Exception {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userService);
		provider.setPasswordEncoder(bCryptPasswordEncoder());

		return provider;
	}

	@Bean
	public JsonLoginProcessFilter jsonLoginProcessFilter() {
		JsonLoginProcessFilter jsonLoginProcessFilter = new JsonLoginProcessFilter(objectMapper, authenticationManager);
		jsonLoginProcessFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
			String token = tokenProvider.createToken(authentication);

			// JWT 토큰을 HTTP 응답으로 반환
			response.setContentType("application/json");
			response.getWriter().write("{\"token\": \"" + token + "\"}");
			//response.getWriter().println("Success Login");
		});
		return jsonLoginProcessFilter;
	}

	@Bean
	AuthenticationManager authenticationManager(
			AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();

		config.setAllowCredentials(true);
		config.setAllowedOrigins(List.of("http://localhost:4200"));
		config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
		config.setAllowedHeaders(List.of("*"));
		config.setExposedHeaders(List.of("*"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}

}
