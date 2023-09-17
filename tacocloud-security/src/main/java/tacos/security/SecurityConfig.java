package tacos.security;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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
import org.springframework.http.MediaType;
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
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tacos.security.jwt.*;
import tacos.security.oauth2.OAuth2UserService;

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

	private final OAuth2UserService oAuth2UserService;

	public SecurityConfig(@Lazy UserDetailsService userService,
						  @Lazy JsonLoginProcessFilter jsonLoginProcessFilter,
						  ObjectMapper objectMapper,
						  JwtAccessDeniedHandler jwtAccessDeniedHandler,
						  JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
						  JwtFilter jwtFilter,
						  @Lazy AuthenticationManager authenticationManager,
						  TokenProvider tokenProvider,
						  OAuth2UserService oAuth2UserService
						  ) {
		this.userService = userService;
		this.jsonLoginProcessFilter = jsonLoginProcessFilter;
		this.objectMapper = objectMapper;
		this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
		this.jwtFilter = jwtFilter;
		this.authenticationManager = authenticationManager;
		this.tokenProvider = tokenProvider;
		this.oAuth2UserService = oAuth2UserService;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity
				.authorizeHttpRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다.
				.requestMatchers("/login", "/registry", "/loginKakao").permitAll() // 로그인 api
				.anyRequest().authenticated()

				.and()
				.csrf().disable() // 외부 POST 요청을 받아야하니 csrf는 꺼준다.
				.cors().configurationSource(corsConfigurationSource())
				.and().httpBasic().realmName("Taco Cloud")
				.and().logout().logoutSuccessUrl("/")
				.and().headers().frameOptions().sameOrigin();

		httpSecurity
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(jsonLoginProcessFilter, UsernamePasswordAuthenticationFilter.class)
				.authenticationProvider(daoAuthenticationProvider())
				.exceptionHandling()
				.accessDeniedHandler(jwtAccessDeniedHandler)
				.authenticationEntryPoint(jwtAuthenticationEntryPoint)
				.and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션을 사용하지 않겠다

		httpSecurity
				.oauth2Login()
				.loginPage("/loginKakao")
				.successHandler(successHandler())
				.userInfoEndpoint()
				.userService(oAuth2UserService);
		return httpSecurity.build();
	}

	@Bean
	public AuthenticationSuccessHandler successHandler() {
		return ((request, response, authentication) -> {
			DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();

			String token = tokenProvider.createToken(authentication);

			// JWT 토큰을 HTTP 응답으로 반환
			response.setContentType("application/json");
			response.getWriter().write("{\"token\": \"" + token + "\"}");

//			String id = defaultOAuth2User.getAttributes().get("id").toString();
//			String body = """
//                    {"id":"%s"}
//                    """.formatted(id);
//
//			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//			response.setCharacterEncoding(StandardCharsets.UTF_8.name());
//
//			PrintWriter writer = response.getWriter();
//			writer.println(body);
//			writer.flush();
		});
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
